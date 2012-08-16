import logging
import os
import random

from google.appengine.ext.webapp import template

try: import simplejson as json
except ImportError: import json

from abstract_app import AbstractApp
from model import UserToken, ContentInfo


class NotAlone(AbstractApp):
  def contentGet(self, client, content_info):
    content_json = json.loads(content_info.content)
    fsqCallback = self.request.get('fsqCallback')
    if content_info.reply_id:
      content_json["content_id"] = content_info.content_id
      content_json["fsqCallback"] = fsqCallback
      if len(content_json['connected']) == 0:
        path = os.path.join(os.path.dirname(__file__), 'instructions.html')
        self.response.out.write(template.render(path, content_json))
      else:
        path = os.path.join(os.path.dirname(__file__), 'reply.html')
        self.response.out.write(template.render(path, content_json))
    
    elif content_info.post_id:
      logging.error('Received unexpected post content id');

  def appPost(self, client):
    sci = self.request.get('source_content_id')
    source_content_info = self.fetchContentInfo(sci)
    access_token = self.fetchAccessToken(source_content_info.fs_id)
    
    client.set_access_token(access_token)
    checkin_json = client.checkins(source_content_info.checkin_id)['checkin']
    venueId = checkin_json['venue']['id']
    shout = '%s says: I am not alone' % checkin_json['user']['firstName']
    newCheckin = dict({'venueId': venueId, 'broadcast': 'public', 'shout': shout})
    if 'event' in checkin_json:
      newCheckin['eventId'] = checkin_json['event']['id']

    successNames = []
    connectedTokens = json.loads(source_content_info.content)['connected']
    tokenNamePairs = [(UserToken.get_by_fs_id(token[0]), token[1]) for token in connectedTokens]
    for tokenNamePair in tokenNamePairs:
      if tokenNamePair[0] is not None:
        client.set_access_token(tokenNamePair[0].token)
        client.checkins.add(newCheckin)
        # check for error?
        successNames.append(tokenNamePair[1])

    client.set_access_token(access_token) # restore token to original user
    message = "You just checked-in: %s" % ", ".join(successNames)
    self.makeContentInfo( checkin_json = checkin_json,
                          content = json.dumps({'successNames': successNames, 'message': message}),
                          text = message,
                          post = True)

    # TODO(ak): Use fsqCallback
    fsqCallback = self.request.get('fsqCallback')
    logging.debug('fsqCallback = %s' % fsqCallback)
    self.redirect(fsqCallback)
        
  
  def checkinTaskQueue(self, client, checkin_json):
    venue_id = checkin_json['venue']['id']
    venue_json = client.venues(venue_id)['venue']
    if 'entities' in checkin_json:
      mentionedIds = [entity['id'] for entity in checkin_json['entities'] if entity['type'] == 'user']
      friends = [friend for friend in client.users.friends()['friends']['items'] if friend['id'] in mentionedIds]
      tokens = [(friend, UserToken.get_by_fs_id(friend['id'])) for friend in friends]
      connectedTokenNamePairs = [(token[0]['id'], token[0]['firstName']) for token in tokens if token[1] is not None]
      unconnectedTokenNamePairs = [(token[0]['id'], token[0]['firstName']) for token in tokens if token[1] is None]
      logging.info('{0} -> {1}'.format(connectedTokenNamePairs, unconnectedTokenNamePairs))
    else:
      connectedTokenNamePairs = []
      unconnectedTokenNamePairs = []

    connectedFriendNames = ", ".join([y[1] for y in connectedTokenNamePairs])
    unconnectedFriendNames = ", ".join([y[1] for y in unconnectedTokenNamePairs])
                                
                                     
    if len(connectedTokenNamePairs) == 0 and len(unconnectedTokenNamePairs) == 0:
      message = 'Mention your friends in your check-in and you can help them check in!'
    elif len(connectedTokenNamePairs) == 0 and len(unconnectedTokenNamePairs) > 0:
      message = 'Tell your lazy friends (%s) to connect the app so you may help them check in.' % unconnectedFriendNames
    elif len(connectedTokenNamePairs) > 0 and len(unconnectedTokenNamePairs) > 0:
      message = 'Automatic check-in for some of your friends (%s) but not all (%s) since they have not connected the app' % (
                connectedFriendNames, unconnectedFriendNames)
    else: # connectedTokenNamePairs > 0 and unconnectedTokenNamePairs == 0
      message = 'Automatic check-in for your friends (%s)' % connectedFriendNames
      
    self.makeContentInfo( checkin_json = checkin_json,
                          content = json.dumps({'connected': connectedTokenNamePairs,
                                                'unconnected': unconnectedTokenNamePairs,
                                                'title': message}),
                          text = message,
                          reply = True)      
      

