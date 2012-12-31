import random
import string

from google.appengine.ext import db

class UserSession(db.Model):
  """Maps user cookies back to foursquare ids."""
  fs_id = db.StringProperty()
  session = db.StringProperty()

  @staticmethod
  def get_or_create_session(user_id):
    session = UserSession().all().filter('fs_id =', user_id).get()
    if not session:
      session = UserSession()
      session.fs_id = user_id
      session.session = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(64))
      session.put()
    return session

  @staticmethod
  def get_from_cookie(cookie):
    return UserSession().all().filter('session =', cookie).get()


class UserToken(db.Model):
  """Contains the user to foursquare_id + oauth token mapping."""
  fs_id = db.StringProperty()
  token = db.StringProperty()

  @staticmethod
  def get_by_fs_id(fs_id):
    return UserToken().all().filter('fs_id =', fs_id).get()

  @staticmethod
  def fetch_by_fs_ids(ids):
    result = []
    # IN query limited to 30
    # https://developers.google.com/appengine/docs/python/datastore/queries#Retrieving_Results
    for i in range(0, len(ids), 30):
      chunk = ids[i: i + 30]
      result += UserToken().all().filter('fs_id IN', chunk).run(limit = 30)
    return result

  @staticmethod
  def get_from_cookie(cookie):
    session = UserSession.get_from_cookie(cookie)
    if session:
      return UserToken.get_by_fs_id(session.fs_id)
    return None

class ContentInfo(db.Model):
  """Generic object for easily storing content for a reply or post."""
  content_id = db.StringProperty()
  checkin_id = db.StringProperty()
  venue_id = db.StringProperty()
  fs_id = db.TextProperty()
  content = db.TextProperty()
  reply_id = db.TextProperty()
  post_id = db.TextProperty()

  @staticmethod
  def get_checkin_reply(checkin_id):
    # To avoid index error, we get the reply by filtering for rows where the post_id is NULL
    return ContentInfo().all().filter('checkin_id =', checkin_id).filter('post_id =', None).get()

class UserSettings(db.Model):
  """Settings for each user"""
  fs_id = db.StringProperty()
  permissions = db.TextProperty()

  @staticmethod
  def get_by_fs_id(fs_id):
    return UserSettings().all().filter('fs_id =', fs_id).get()

  @staticmethod
  def fetch_by_fs_ids(ids):
    result = []
    # IN query limited to 30
    # https://developers.google.com/appengine/docs/python/datastore/queries#Retrieving_Results
    for i in range(0, len(ids), 30):
      chunk = ids[i: i + 30]
      result += UserSettings().all().filter('fs_id IN', chunk).run(limit = 30)
    return result

class CheckinHistory(db.Model):
  """History information of checkins generated."""
  source_fs_id = db.StringProperty()
  target_fs_id = db.StringProperty()
  target_fs_name = db.TextProperty()
  time = db.DateTimeProperty(auto_now_add=True)