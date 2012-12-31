import logging
import os
import random
import urllib

from google.appengine.api import memcache
from google.appengine.api import taskqueue
from google.appengine.ext.webapp import template
import webapp2

try: import simplejson as json
except ImportError: import json

from config import CONFIG
from model import UserToken, ContentInfo, UserSettings, CheckinHistory, UserSession
import utils

from foursquare import InvalidAuth

class NotAlone(webapp2.RequestHandler):


  # We want to only save the core/critical part of the checkin
  def checkinToCore(self, checkinJson):
    coreCheckin = {}
    coreCheckin['id'] = checkinJson['id']
    coreCheckin['venue'] = {'id': checkinJson['venue']['id']}
    coreCheckin['user'] = {'id': checkinJson['user']['id'], 'firstName': checkinJson['user']['firstName']}
    if 'event' in checkinJson:
      coreCheckin['event'] = {'id': checkinJson['event']['id']}
    if 'entities' in checkinJson:
      coreCheckin['entities'] = checkinJson['entities']
    return coreCheckin


  # Get checkin by either (a) cached by checkinId, (b) saved by content reply, or (c) via Foursquare request
  def getCoreCheckin(self, checkinId, client):
    checkinCacheValue = memcache.get('checkin:%s' % checkinId)
    if checkinCacheValue is not None:
      return checkinCacheValue
    else:
      contentInfo = ContentInfo.get_checkin_reply(checkinId)
      content_json = {}
      if contentInfo is not None:
        content_json = json.loads(contentInfo.content)

      coreCheckin = {}
      if (content_json is not None and 'coreCheckin' in content_json):
        coreCheckin = content_json['coreCheckin']
      else:
        coreCheckin = self.checkinToCore(client.checkins(checkinId)['checkin'])

      # Cache checkin for 1 hour
      if not memcache.set('checkin:%s' % checkinId, coreCheckin, 3600):
        logging.error('Memcache set failed on checkin %s' % checkinId)

      return coreCheckin


  def getUserIdFromToken(self, token):
    try:
      client = utils.makeFoursquareClient(token)
      user = client.users()['user']
      return user['id']
    except InvalidAuth:
      return None


  # Formats a token for storage in cache.
  # We do not store 'None' in the cache, so we convert to a string
  def tokenToCache(self, token):
    if (token is None):
      return 'user_not_connected'
    else:
      return token


  # Formats a user token for storage in cache.
  # We do not store 'None' in the cache, so we convert from a string
  def cacheToToken(self, cacheValue):
    if (cacheValue == 'user_not_connected'):
      return None
    else:
      return cacheValue

  def fetchAccessToken(self, userId):
    return self.fetchAccessTokens([userId]).get(userId)

  def fetchAccessTokens(self, userIds):
    dictFromCache = memcache.get_multi(userIds, key_prefix="token:")
    idsInCache = dictFromCache.keys()
    cachedTokens = {id : self.cacheToToken(dictFromCache[id]) for id in idsInCache}

    idsMissingFromCache = list(set(userIds) - set(idsInCache))
    fetchedTokens = {x.fs_id : x.token for x in UserToken.fetch_by_fs_ids(idsMissingFromCache)}

    if idsMissingFromCache:
      # Add all missing ones that we just fetched to the cache
      failedKeys = memcache.set_multi({id : self.tokenToCache(fetchedTokens.get(id)) for id in idsMissingFromCache},
                                      key_prefix="token:", time=86400)
      if failedKeys:
        logging.error('Memcache set failed on tokens for %s' % ', '.join(failedKeys))

    cachedTokens.update(fetchedTokens)
    return cachedTokens

  def verifiedAccessToken(self, userId, suppliedToken):
    savedToken = self.fetchAccessToken(userId)
    if (savedToken == suppliedToken):
      return suppliedToken
    elif (self.getUserIdFromToken(suppliedToken) == userId):
      # save updated token if record exists, or create a new record
      savedTokenObj = UserToken.get_by_fs_id(userId)
      if savedTokenObj is not None:
        newToken = savedTokenObj
      else:
        newToken = UserToken()

      newToken.token = suppliedToken
      newToken.fs_id = userId
      newToken.put()

      if not memcache.set('token:%s' % userId, self.tokenToCache(suppliedToken), 86400):
        logging.error('Memcache set failed on token for %s' % user_id)
        memcache.delete('token:%s' % userId)

      return suppliedToken
    else:
      return None


  #
  # Get
  #
  def get(self):
    if self.request.path.startswith('/friendjson'):
      return self.getAllowedFriendsJson()
    elif self.request.path.startswith('/settingsjson'):
      return self.getUserSettingsJson()
    elif self.request.path.startswith('/isAuthd'):
      return self.getAuthdStatus()
    elif self.request.path.startswith('/logout'):
      return self.logout()

    self.error(404)

  def logout(self):
    cookie = self.request.cookies.get('session', None)
    if cookie:
      session = UserSession.get_from_cookie(cookie)
      if session:
        session.delete()

    isMobile = utils.isMobileUserAgent(self.request.headers['User-Agent'])
    redirect_uri = CONFIG['auth_success_uri_mobile'] if isMobile else CONFIG['auth_success_uri_desktop']
    self.redirect(redirect_uri)


  def getAuthdStatus(self):

    # Allow cross domain access from http://www.herewithfriends.com and http://u-r-not-alone.appspot.com
    if (self.request.headers.get('Origin') == "http://www.herewithfriends.com"
        and self.request.headers.get('Host') == "u-r-not-alone.appspot.com"):
      self.response.headers.add_header("Access-Control-Allow-Origin", "http://www.herewithfriends.com")
      self.response.headers.add_header("Access-Control-Allow-Credentials", "true")

    elif (self.request.headers.get('Origin') == "http://u-r-not-alone.appspot.com"
          and self.request.headers.get('Host') == "u-r-not-alone.appspot.com"):
      self.response.headers.add_header("Access-Control-Allow-Origin", "http://u-r-not-alone.appspot.com")
      self.response.headers.add_header("Access-Control-Allow-Credentials", "true")

    user_token = UserToken.get_from_cookie(self.request.cookies.get('session', None))
    is_authd = False
    name = ''
    settingsSummary = ''
    settingsLink = ''
    if user_token is not None and user_token.fs_id:
      client = utils.makeFoursquareClient(user_token.token)
      try:
        user = client.users()['user']
        tokenId = user['id']
        if (tokenId != user_token.fs_id):
          is_authd = False
          user_token.delete()
        else:
          is_authd = True
          name = (user.get('firstName', '') + ' ' + user.get('lastName', '')).strip(),
          settingsSummary = self.getPermissionsSummary(user_token.fs_id)
          settingsLink = "%s/settings?userId=%s&access_token=%s" % (
                          utils.getServer(), user_token.fs_id, user_token.token)

      except InvalidAuth:
        user_token.delete()

    self.response.out.write(json.dumps({'connected': is_authd,
                                        'name': name,
                                        'settingsSummary': settingsSummary,
                                        'settingsLink' : settingsLink}))


  def getAllowedFriendsJson(self):
    userId = self.request.get('userId')
    checkinId = self.request.get('checkinId')
    token = self.request.get('access_token')

    access_token = self.verifiedAccessToken(userId, token)
    if (access_token):
      client = utils.makeFoursquareClient(access_token)
      checkin_json = self.getCoreCheckin(checkinId, client)
      venue_id = checkin_json['venue']['id']
      friends = client.users.friends()['friends']['items']
      allFriendIds = [friend['id'] for friend in friends if (friend.get('relationship', 'friend') == 'friend')]
      allowedFriendIds = self.getFriendTokens(userId, allFriendIds).keys()
      friendInfo = [
        {'name': (friend.get('firstName', '') + ' ' + friend.get('lastName', '')).strip(),
         'id': friend['id']}
         for friend in friends if friend['id'] in allowedFriendIds]
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
    return self.fetchPermissions([userId]).get(userId)

  #
  # Gets the security settings for a list of user ids
  #
  def fetchPermissions(self, userIds):
    cachedPermissions = memcache.get_multi(userIds, key_prefix="settings:")

    idsMissingFromCache = list(set(userIds) - set(cachedPermissions.keys()))
    fetchedPermissions = {x.fs_id : json.loads(x.permissions) for x in UserSettings.fetch_by_fs_ids(idsMissingFromCache)}
    # If no permissions are set, the default is to allow all
    defaultedPermissions = {id : {'allowAll': True, 'authorizedFriends': []} for id in idsMissingFromCache
      if fetchedPermissions.get(id) is None
    }
    fetchedPermissions.update(defaultedPermissions)

    if idsMissingFromCache:
      # Add all missing ones that we just fetched to the cache
      failedKeys = memcache.set_multi(fetchedPermissions, key_prefix="settings:", time=86400)
      if failedKeys:
        logging.error('Memcache set failed on settings for %s' % ', '.join(failedKeys))

    cachedPermissions.update(fetchedPermissions)
    return cachedPermissions

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
        elif (numAuthorized == 1):
          return '1 friend can check you in.'
        else:
          return '%s friends can check you in.' % numAuthorized
    except Exception:
      return '(error receiving settings)'


  #
  # Precondition: given user and a list of friends
  # returns a dictionary {friend: token} for all friends that the user is allowed
  #
  def getFriendTokens(self, userId, friendIds):
    userTokenDict = self.fetchAccessTokens(friendIds)
    friendsWithTokens = [id for id in userTokenDict.keys() if userTokenDict[id] is not None]
    friendsPermissions = self.fetchPermissions(friendsWithTokens)
    return {id : userTokenDict.get(id) for id in friendsWithTokens
      if friendsPermissions.get(id) is not None
      and (friendsPermissions.get(id).get('allowAll') or userId in friendsPermissions.get(id).get('authorizedFriends'))
    }


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

      if not memcache.set('settings:%s' % userId, permissions, 86400):
        logging.error('Memcache set failed on settings for %s' % userId)
        memcache.delete('settings:%s' % userId)

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

      checkin_json = self.getCoreCheckin(checkinId, client)
      venueId = checkin_json['venue']['id']
      sourceName = checkin_json['user']['firstName']
      sourceId = checkin_json['user']['id']
      if (sourceId != userId):
        logging.error("User %s attempted to access checkin for user %s" % (userId, sourceId))
        self.error(400)
        return
      successComment = 'Check-in by %s.' % sourceName.encode('utf-8')
      newCheckin = dict({'venueId': venueId, 'broadcast': 'public', 'shout': successComment})
      if 'event' in checkin_json:
        newCheckin['eventId'] = checkin_json['event']['id']

      friends = client.users.friends()['friends']['items']
      allFriendIds = [friend['id'] for friend in friends if (friend.get('relationship', 'friend') == 'friend')]
      allowedFriendTokens = self.getFriendTokens(userId, allFriendIds)

      successNames = []
      disconnectedNames = []

      for selectedUserId in selectedUserIds:
        matching = [friend for friend in friends if friend['id'] == selectedUserId]
        token = allowedFriendTokens.get(selectedUserId)
        if (len(matching) > 0 and token is not None):
          friendObj = matching[0]
          client.set_access_token(token)
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

            ## successComment moved to shout instead of post due to complaints
            # self.makeContentInfo( checkin_json = friendCheckin,
            #                       content = json.dumps({'checkinFrom': sourceName}),
            #                       text = successComment,
            #                       post = True)
          except InvalidAuth:
            # If a user disconnects the app, we can then have an invalid token
            logging.info('invalid oauth - deleting token for %s' % friendObj['id'])
            disconnectedNames.append(friendObj['firstName'])
            tokenObj = UserToken.get_by_fs_id(selectedUserId)
            if (tokenObj is not None):
              tokenObj.delete()
              memcache.delete('token:%s' % selectedUserId)

          except Exception as inst:
            logging.error('Failed to check in user %s-%s: %s' % (friendObj['firstName'], friendObj['id'], str(inst)))

      client.set_access_token(access_token) # restore token to original user
      successNamesStr = ", ".join(successNames)
      disconnectedNamesStr = ", ".join(disconnectedNames)

      if (len(successNames) > 0):
        message = "You just checked in: %s" % successNamesStr
        self.makeContentInfo( checkin_json = checkin_json,
                              content = json.dumps({'successNames': successNames, 'message': message}),
                              text = message,
                              post = True)

      if (len(disconnectedNames) > 0):
        message = "Failed to check in the following users as they have disconnected the app: %s" % disconnectedNamesStr
        self.makeContentInfo( checkin_json = checkin_json,
                              content = json.dumps({'disconnectedNames': disconnectedNames, 'message': message}),
                              text = message,
                              post = True)

      logging.info('%s (%s) checked in: %s' % (sourceName, sourceId, successNamesStr))
      self.response.out.write(json.dumps({'successNames': successNames}))


  def checkinTaskQueue(self, client, checkin_json, userId, checkinId, access_token):
    venue_id = checkin_json['venue']['id']

    urlParams = { 'userId' : userId, 'checkinId' : checkinId, 'access_token' : access_token }
    url = '%s/content?%s' % (utils.getServer(), urllib.urlencode(urlParams))

    message = 'Check in your friends'
    coreCheckin = self.checkinToCore(checkin_json)

    self.makeContentInfo( checkin_json = checkin_json,
                          content = json.dumps({'coreCheckin': coreCheckin}),
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
      params['text'] = text.encode('utf-8')
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

      

