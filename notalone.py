import logging
import os
import random

from google.appengine.api import taskqueue
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template

try: import simplejson as json
except ImportError: import json

from config import CONFIG
from model import UserToken, ContentInfo
import utils

from foursquare import InvalidAuth

class NotAlone(webapp.RequestHandler):

  def fetchAccessToken(self, user_id):
    request = UserToken.all()
    request.filter("fs_id = ", str(user_id))
    user_token = request.get()
    return user_token.token if user_token else None

  def fetchContentInfo(self, content_id):
    request = ContentInfo.all().filter("content_id = ", content_id)
    return request.get()

  #
  # Get
  #
  def get(self):
    client = utils.makeFoursquareClient()
    content_id = self.request.get('content_id')
    if content_id:
      content_info = ContentInfo.all().filter('content_id =', content_id).get()
      if not content_info:
        self.error(404)
        return
      elif self.request.path.startswith('/contentjson'):
        return self.contentGetJson(client, content_info)

    self.error(404)

  def contentGetJson(self, client, content_info):
    access_token = self.fetchAccessToken(content_info.fs_id)
    client.set_access_token(access_token)
    checkin_json = client.checkins(content_info.checkin_id)['checkin']
    venue_id = checkin_json['venue']['id']
    friends = [friend for friend in client.users.friends()['friends']['items']]
    friendInfo = [
      {'name': (friend.get('firstName', '') + ' ' + friend.get('lastName', '')).strip(),
       'id': friend['id']}
       for friend in friends if (friend.get('relationship', 'friend') == 'friend') and (UserToken.get_by_fs_id(friend['id']) is not None)]
    friendInfoSorted = sorted(friendInfo, key=lambda x: x['name'].upper())

    content_json = json.loads(content_info.content)
    mentions = content_json.get('mentions')
    if (mentions is None):
      mentions = [];

    if content_info.reply_id:
      self.response.out.write(json.dumps({'friendInfo': friendInfoSorted, 'mentions': mentions}))

    elif content_info.post_id:
      logging.error('Received unexpected post content id');


  def friendCheckin(self, client):
    taskqueue.add(url='/_friend-checkin',
                  params={'source_content_id': self.request.get('source_content_id'),
                          'selected': self.request.get('selected')})
    self.response.out.write(json.dumps({'status': 'ok'}))

  #
  # Post
  #
  def post(self):
    if self.request.path.startswith('/_checkin') and self.request.get('checkin'):
      # Parse floats as string so we don't lose lat/lng precision. We can use Decimal later.
      checkin_json = json.loads(self.request.get('checkin'),
                                parse_float=str)
      user_id = checkin_json['user']['id']
      access_token = self.fetchAccessToken(user_id)
      if not access_token:
        logging.warning('Received push for unknown user_id {}'.format(user_id))
        return
      client = utils.makeFoursquareClient(access_token)
      return self.checkinTaskQueue(client, checkin_json)
    elif self.request.path.startswith('/friend-checkin'):
      client = utils.makeFoursquareClient()
      return self.friendCheckin(client)
    elif self.request.path.startswith('/_friend-checkin'):
      client = utils.makeFoursquareClient()
      return self.friendCheckinTaskQueue(client)

    client = utils.makeFoursquareClient()
    self.error(404)

  #
  # Queue
  #
  def friendCheckinTaskQueue(self, client):
    sci = self.request.get('source_content_id')
    logging.debug('source_content_id = %s' % sci)

    selectedUserParam = self.request.get('selected')
    logging.debug('selected = %s' % selectedUserParam)
    selectedUserIds = selectedUserParam.split('-')

    source_content_info = self.fetchContentInfo(sci)
    access_token = self.fetchAccessToken(source_content_info.fs_id)
    client.set_access_token(access_token)

    checkin_json = client.checkins(source_content_info.checkin_id)['checkin']
    venueId = checkin_json['venue']['id']
    sourceName = checkin_json['user']['firstName']
    sourceId = checkin_json['user']['id']
    successComment = 'Check-in by %s.' % sourceName
    newCheckin = dict({'venueId': venueId, 'broadcast': 'public'})
    if 'event' in checkin_json:
      newCheckin['eventId'] = checkin_json['event']['id']

    allowedFriends = client.users.friends()['friends']['items']
    successNames = []

    for selectedUserId in selectedUserIds:
      matching = [friend for friend in allowedFriends if friend['id'] == selectedUserId]
      tokenObj = UserToken.get_by_fs_id(selectedUserId)
      if (len(matching) > 0 and tokenObj is not None):
        friendObj = matching[0];
        client.set_access_token(tokenObj.token)
        try:
          friendCheckin = client.checkins.add(newCheckin)['checkin']
          if 'user' not in friendCheckin:
            friendCheckin['user'] = {'id': friendObj['id'], 'firstName': friendObj['firstName']}
          successNames.append(friendObj['firstName'])
          self.makeContentInfo( checkin_json = friendCheckin,
                                content = json.dumps({'checkinFrom': sourceName}),
                                text = successComment,
                                post = True)
        except InvalidAuth:
          # If a user disconnects the app, we can then have an invalid token
          logging.info('invalid oauth - deleting token')
          tokenObj.delete()
        except Exception as inst:
          logging.error('Failed to check in user %s-%s' % (friendObj['firstName'], friendObj['id']))

    client.set_access_token(access_token) # restore token to original user
    successNamesStr = ", ".join(successNames)
    if (len(successNames) > 0):
      message = "You just checked-in: %s" % successNamesStr
      self.makeContentInfo( checkin_json = checkin_json,
                            content = json.dumps({'successNames': successNames, 'message': message}),
                            text = message,
                            post = True)

    logging.info('%s (%s) checked in: %s' % (sourceName, sourceId, successNamesStr))
    self.response.out.write(json.dumps({'successNames': successNames}))


  def checkinTaskQueue(self, client, checkin_json):
    venue_id = checkin_json['venue']['id']
    venue_json = client.venues(venue_id)['venue']
    if 'entities' in checkin_json:
      mentionedIds = [entity['id'] for entity in checkin_json['entities'] if entity['type'] == 'user']
    else:
      mentionedIds = []

    message = 'Check in your friends'

    self.makeContentInfo( checkin_json = checkin_json,
                          content = json.dumps({'mentions': mentionedIds}),
                          text = message,
                          reply = True)

  def makeContentInfo(self,
                      checkin_json,
                      content,
                      url=None,
                      text=None, photoId=None,
                      reply=False, post=False):
    assert (reply ^ post), "Must pass exactly one of reply or post"
    assert (text or photoId)

    # Avoid posting duplicate content.
    request = ContentInfo.all()
    request = request.filter('checkin_id = ', checkin_json['id'])
    existing_contents = request.fetch(10)
    for existing_content in existing_contents:
      # Check that they're the same type of content
      if existing_content.reply_id and not reply:
        continue
      if existing_content.post_id and not post:
        continue
      # Check if the content payload is the same
      if existing_content.content == content:
        logging.info('Avoided posting duplicate content %s' % content)
        return existing_content

    content_id = utils.generateId()
    checkin_id = checkin_json['id']

    content_info = ContentInfo()
    content_info.content_id = content_id
    content_info.fs_id = checkin_json['user']['id']
    content_info.checkin_id = checkin_id
    content_info.venue_id = checkin_json['venue']['id']
    content_info.content = content
    if not url:
      url = utils.generateContentUrl(content_id)

    access_token = self.fetchAccessToken(content_info.fs_id)
    client = utils.makeFoursquareClient(access_token)

    params = {'contentId' : content_id,
              'url' : url}
    if text:
      params['text'] = text
    if photoId:
      params['photoId'] = photoId

    logging.info('creating content with params=%s' % params)

    if post:
      if CONFIG['local_dev']:
        content_info.post_id = utils.generateId()
      else:
        response_json = client.checkins.addpost(checkin_id, params)
        content_info.post_id = response_json['post']['id']
    elif reply:
      if CONFIG['local_dev']:
        content_info.reply_id = utils.generateId()
      else:
        response_json = client.checkins.reply(checkin_id, params)
        reply_id = None
        if 'replies' in response_json:
          reply_id = response_json['replies']['id']
        elif 'reply' in response_json:
          # Right now we return "replies" but we should probably return "reply"
          # adding this so I don't have to do it later in the event we rename
          reply_id = response_json['reply']['id']
        else:
          logging.error("Could not find reply id in /checkins/reply response: %s" % response_json)

        content_info.reply_id = reply_id

    content_info.put()

    return content_info

      

