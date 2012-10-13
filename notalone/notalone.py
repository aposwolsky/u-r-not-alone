import logging
import os
import random

from google.appengine.api import taskqueue
from google.appengine.ext.webapp import template

try: import simplejson as json
except ImportError: import json

from abstract_app import AbstractApp
from model import UserToken, ContentInfo


class NotAlone(AbstractApp):
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
      

