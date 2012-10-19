import logging
import os
import random
import urllib

from google.appengine.api import taskqueue
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template

try: import simplejson as json
except ImportError: import json

from config import CONFIG
from model import UserToken, ContentInfo, UserSettings, CheckinHistory
import utils

from foursquare import InvalidAuth

class NotAlone(webapp.RequestHandler):

  def getUserIdFromToken(self, token):
    try:
      client = utils.makeFoursquareClient(token)
      user = client.users()
      return user['user']['id']
    except InvalidAuth:
      return None

  def verifiedAccessToken(self, userId, suppliedToken):
    request = UserToken.all()
    request.filter("fs_id = ", str(userId))
    savedTokenObj = request.get()
    if (savedTokenObj and savedTokenObj.token == suppliedToken):
      return suppliedToken
    elif (self.getUserIdFromToken(suppliedToken) == userId):
      # save updated token
      if savedTokenObj:
        newToken = savedTokenObj
      else:
        newToken = UserToken()

      newToken.token = suppliedToken
      newToken.fs_id = userId
      newToken.put()
      return suppliedToken
    else:
      return None


  def fetchAccessToken(self, user_id):
    request = UserToken.all()
    request.filter("fs_id = ", str(user_id))
    user_token = request.get()
    return user_token.token if user_token else None

  #
  # Get
  #
  def get(self):
    if self.request.path.startswith('/friendjson'):
      return self.getAllowedFriendsJson()
    elif self.request.path.startswith('/settingsjson'):
      return self.getUserSettingsJson()

    self.error(404)

  def getAllowedFriendsJson(self):
    userId = self.request.get('userId')
    checkinId = self.request.get('checkinId')
    token = self.request.get('access_token')

    access_token = self.verifiedAccessToken(userId, token)
    if (access_token):
      client = utils.makeFoursquareClient(access_token)
      checkin_json = client.checkins(checkinId)['checkin']
      venue_id = checkin_json['venue']['id']
      friends = [friend for friend in client.users.friends()['friends']['items']]
      friendInfo = [
        {'name': (friend.get('firstName', '') + ' ' + friend.get('lastName', '')).strip(),
         'id': friend['id']}
         for friend in friends if (friend.get('relationship', 'friend') == 'friend')
                               and (self.getUserToken(userId, friend['id']) is not None)]
      friendInfoSorted = sorted(friendInfo, key=lambda x: x['name'].upper())

      if 'entities' in checkin_json:
        mentionedIds = [entity['id'] for entity in checkin_json['entities'] if entity['type'] == 'user']
      else:
        mentionedIds = []

      settingsSummary = self.getPermissionsSummary(userId)
      self.response.out.write(json.dumps({'friendInfo': friendInfoSorted,
                                          'mentions': mentionedIds,
                                          'settingsSummary': settingsSummary}))

    else:
      self.error(404)

  #
  # Gets the security settings for userId
  #
  def getPermissions(self, userId):
    settingsObj = UserSettings.get_by_fs_id(userId)
    if settingsObj:
      return json.loads(settingsObj.permissions)
    else:
      return {'allowAll': True, 'authorizedFriends': []}

  #
  # Permissions Summary
  #
  def getPermissionsSummary(self, userId):
    try:
      permissions = self.getPermissions(userId)
      if (permissions.get('allowAll')):
        return 'All friends can check you in.'
      else:
        numAuthorized = len(permissions.get('authorizedFriends'))
        if (numAuthorized == 0):
          return 'No one can check you in.'
        else:
          return '%s of your friends can check you in.' % numAuthorized
    except Exception:
      return '(error receiving settings)'


  #
  # Precondition: given two friends checkinSource and checkinTarget
  # returns whether checkinSource is allowed to check in checkinTarget
  #
  def isAllowed(self, checkinSource, checkinTarget):
    try:
      targetPermissions = self.getPermissions(checkinTarget)
      if (targetPermissions.get('allowAll') or checkinSource in targetPermissions.get('authorizedFriends')):
        return True
      else:
        return False
    except Exception:
      logging.error('Failed to check whether %s can check in %s' % (checkinSource, checkinTarget))
      return False

  #
  # Precondition: given two friends checkinSource and checkinTarget
  # returns a token for checkinTarget if checkinSource is allowed
  #
  def getUserToken(self, checkinSource, checkinTarget):
    token = UserToken.get_by_fs_id(checkinTarget)
    if (token is not None and self.isAllowed(checkinSource, checkinTarget)):
      return token
    else:
      return None


  def getUserSettingsJson(self):
    userId = self.request.get('userId')
    token = self.request.get('access_token')

    access_token = self.verifiedAccessToken(userId, token)
    if (access_token):
      client = utils.makeFoursquareClient(access_token)
      friends = [friend for friend in client.users.friends()['friends']['items']]
      friendInfo = [
        {'name': (friend.get('firstName', '') + ' ' + friend.get('lastName', '')).strip(),
         'id': friend['id']}
         for friend in friends if (friend.get('relationship', 'friend') == 'friend')]
      friendInfoSorted = sorted(friendInfo, key=lambda x: x['name'].upper())

      permissions = self.getPermissions(userId)
      self.response.out.write(json.dumps({'friendInfo': friendInfoSorted, 'permissions': permissions}))

    else:
      self.error(404)

  def friendCheckin(self):
    taskqueue.add(url='/_friend-checkin',
                  params={'userId': self.request.get('userId'),
                          'checkinId': self.request.get('checkinId'),
                          'access_token': self.request.get('access_token'),
                          'selected': self.request.get('selected')})
    self.response.out.write(json.dumps({'status': 'ok'}))

  def changeUserSettings(self):
    userId = self.request.get('userId')
    token = self.request.get('access_token')

    access_token = self.verifiedAccessToken(userId, token)
    if (access_token):
      allowAllParam = self.request.get('allowAll')
      selectedParam = self.request.get('authorizedFriends')
      logging.debug('changeUserSettings for user %s. allowAll=%s authorizedFriends=%s' %
                     (userId, allowAllParam, selectedParam))

      allowAll = allowAllParam in ['True', 'true', '1']
      if (selectedParam is None or selectedParam.strip() == ""):
        selectedIds = []
      else:
        selectedIds = selectedParam.split('-')

      existingSettingsObj = UserSettings.get_by_fs_id(userId)
      if existingSettingsObj:
        settingsObj = existingSettingsObj
      else:
        settingsObj = UserSettings()

      if (allowAll):
        permissions = {'allowAll': True, 'authorizedFriends': []}
      else:
        permissions = {'allowAll': False, 'authorizedFriends': selectedIds}

      settingsObj.fs_id = userId
      settingsObj.permissions = json.dumps(permissions)
      settingsObj.put()

      logging.info('%s changed settings to: %s' % (settingsObj.fs_id, settingsObj.permissions))
      self.response.out.write(json.dumps({'status': 'ok'}))
    else:
      self.error(404)

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
      return self.checkinTaskQueue(client, checkin_json, user_id, checkin_json.get('id'), access_token)
    elif self.request.path.startswith('/friend-checkin'):
      return self.friendCheckin()
    elif self.request.path.startswith('/_friend-checkin'):
      return self.friendCheckinTaskQueue()
    elif self.request.path.startswith('/change-settings'):
      return self.changeUserSettings()

    self.error(404)
  #
  # Queue
  #
  def friendCheckinTaskQueue(self):
    userId = self.request.get('userId')
    checkinId = self.request.get('checkinId')
    token = self.request.get('access_token')

    access_token = self.verifiedAccessToken(userId, token)
    if (access_token):
      client = utils.makeFoursquareClient(access_token)

      selectedUserParam = self.request.get('selected')
      logging.debug('selected = %s' % selectedUserParam)
      selectedUserIds = selectedUserParam.split('-')

      checkin_json = client.checkins(checkinId)['checkin']
      venueId = checkin_json['venue']['id']
      sourceName = checkin_json['user']['firstName']
      sourceId = checkin_json['user']['id']
      if (sourceId != userId):
        logging.error("User %s attempted to access checkin for user %s" % (userId, sourceId))
        self.error(400)
        return
      successComment = 'Check-in by %s.' % sourceName
      newCheckin = dict({'venueId': venueId, 'broadcast': 'public'})
      if 'event' in checkin_json:
        newCheckin['eventId'] = checkin_json['event']['id']

      allowedFriends = client.users.friends()['friends']['items']
      successNames = []

      for selectedUserId in selectedUserIds:
        matching = [friend for friend in allowedFriends if friend['id'] == selectedUserId]
        tokenObj = self.getUserToken(sourceId, selectedUserId)
        if (len(matching) > 0 and tokenObj is not None):
          friendObj = matching[0]
          client.set_access_token(tokenObj.token)
          try:
            friendCheckin = client.checkins.add(newCheckin)['checkin']
            if 'user' not in friendCheckin:
              friendCheckin['user'] = {'id': friendObj['id'], 'firstName': friendObj['firstName']}
            successNames.append(friendObj['firstName'])

            # Update history
            history = CheckinHistory()
            history.source_fs_id = sourceId
            history.target_fs_id = friendObj['id']
            history.target_fs_name = (friendObj.get('firstName', '') + ' ' + friendObj.get('lastName', '')).strip()
            history.put()

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


  def checkinTaskQueue(self, client, checkin_json, userId, checkinId, access_token):
    venue_id = checkin_json['venue']['id']
    venue_json = client.venues(venue_id)['venue']
    if 'entities' in checkin_json:
      mentionedIds = [entity['id'] for entity in checkin_json['entities'] if entity['type'] == 'user']
    else:
      mentionedIds = []

    urlParams = { 'userId' : userId, 'checkinId' : checkinId, 'access_token' : access_token }
    url = '%s/content?%s' % (utils.getServer(), urllib.urlencode(urlParams))

    message = 'Check in your friends'

    self.makeContentInfo( checkin_json = checkin_json,
                          content = json.dumps({'mentions': mentionedIds}),
                          url = url,
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

    access_token = self.fetchAccessToken(content_info.fs_id)
    client = utils.makeFoursquareClient(access_token)

    if not url:
      params = {}
    else:
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

      

