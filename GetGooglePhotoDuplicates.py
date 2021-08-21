import flask
from flask import request
import google_auth_oauthlib.flow
import google.oauth2.credentials
import json
import os
import requests
import sys
from google.auth.transport.requests import AuthorizedSession
from pprint import pprint
from types import SimpleNamespace


# Google Photos auth
CLIENT_SECRETS_FILE = 'client_secret.json'
outputFileName = 'duplicate-search-output.txt'
visitedFilesFileName='visited-files.txt'
ignoredFilesFileName='ignored-files.txt'
SCOPES = ["https://www.googleapis.com/auth/photoslibrary.readonly"]
API_SERVICE_NAME = 'photos'
API_VERSION = 'v2'

# flask settings
app = flask.Flask(__name__, template_folder="templates")
app.secret_key = 'MySecretAppKey' # TODO: change this if deploying to a server

# app globals
redirect = ""
forceRefresh=False
message = ""
fileCount = 0
duplicateCount = 0
ignoredCount = 0
duplicateHtml = ""
detailedLogging = False
searchTerm = ""
searchHtml = ""
hideIgnored = False

@app.route('/')
def index():
  global message
  return flask.render_template('index.html', message=message)


@app.route('/duplicatePhotos', methods=["POST", "GET"])
def findDuplicatePhotos():
  global redirect
  global hideIgnored

  ignored = 'show' if not hideIgnored else 'hide'
  if request.method == "POST":
    ignored = request.form['ignored']
  hideIgnored = ignored == 'hide'

  if 'credentials' not in flask.session:
    redirect = 'duplicate'
    return flask.redirect('authorize')

  credentials = google.oauth2.credentials.Credentials(**flask.session['credentials'])
  session = AuthorizedSession(credentials)

  return getPhotoData(session)

def getPhotoData(session):
  global fileCount
  global duplicateCount
  global forceRefresh
  global duplicateHtml
  global searchHtml
  global message
  global ignoredCount
  global hideIgnored

  shouldRefreshFile = forceRefresh
  forceRefresh = False
  rawFiles = []
  if outputFileName and os.path.isfile(outputFileName) and not shouldRefreshFile:
    with open(outputFileName, 'r') as f:
      fileContents = f.read().replace('\n', '')
      if len(fileContents) == 0:
        f.close()
      else:
        print('Loaded file names from existing output')
        rawFiles = json.loads(fileContents)
        f.close()
  
  if len(rawFiles) == 0:
    if visitedFilesFileName and os.path.isfile(visitedFilesFileName):
      os.remove(visitedFilesFileName)

    message = "Sending requests to Google Photos API..."
    nextPageToken = ""
    requestCount = 0
    previousRetrieved = 0
    while nextPageToken is not None:
      print(f"Sending request {requestCount}. Previous found {previousRetrieved} records. {f'(Token: {nextPageToken})' if detailedLogging else ''}")
      requestUrl = "https://photoslibrary.googleapis.com/v1/mediaItems?pageSize=100"
      if nextPageToken != "":
        requestUrl += f"&pageToken={nextPageToken}"

      try:
        mediaResponse = session.get(requestUrl).json()
      except e:
        message = f"Error with Google request: {sys.exc_info()[0]}"
        return flask.redirect('/')
      if 'mediaItems' not in mediaResponse:
        if 'error' in mediaResponse:
          return f"There was a problem with the request: {mediaResponse['error']['message']}"
        
        print(mediaResponse)
        return "There was a problem with the request. See log for details."
        
      mediaItems = mediaResponse['mediaItems']
      previousRetrieved = len(mediaItems)
      for item in mediaItems:
        rawFiles.append({
          'filename': item['filename'],
          'id': item['id']
        })

      if 'nextPageToken' in mediaResponse:
        nextPageToken = mediaResponse['nextPageToken']
      else:
        nextPageToken = None
      requestCount+=1

    print(f'Saving raw output to {outputFileName}')
    original_stdout = sys.stdout
    with open(outputFileName, 'w') as f:
      f.write(json.dumps(rawFiles))
      f.close()

  files = processRawFiles(rawFiles)
  duplicates = findDuplicates(files)
  
  visitedFiles = []
  if visitedFilesFileName and os.path.isfile(visitedFilesFileName):
    with open(visitedFilesFileName, 'r') as f:
      visitedFiles = f.read().split('\n')
      f.close()

  ignoredFiles = []
  if ignoredFilesFileName and os.path.isfile(ignoredFilesFileName):
    with open(ignoredFilesFileName, 'r') as f:
      ignoredFiles = f.read().split('\n')
      f.close()

  outputStr = ""
  ignoredCount = 0
  for name in duplicates:
    dupeCount = len(files[name]['ids'])
    dupeTypes = ', '.join(files[name]['endings'])
    visitedStyle = 'text-decoration:line-through;' if name in visitedFiles else ''
    isIgnored = name in ignoredFiles
    if isIgnored:
      ignoredCount += 1
    
    if (isIgnored and not hideIgnored) or not isIgnored:
      ignoredStyle = 'opacity:0.25;color:red;text-decoration:line-through;' if isIgnored else ''  
      line = f"<span style='{ignoredStyle}'><a href='/duplicatePhotos/search/{name}' class='file-name-link' style='{visitedStyle}'>{name}</a> - count: {dupeCount}; types: {dupeTypes}</span> <a href='/duplicatePhotos/{'unignoreFile' if isIgnored else 'ignoreFile'}/{name}' style='margin-left:10px;'>{'Unignore' if isIgnored else 'Ignore'}</a><br/>"
      outputStr += line

  fileCount=len(files)
  duplicateCount=len(duplicates) - ignoredCount
  duplicateHtml=outputStr
  return flask.render_template('data.html', ignoredCount=ignoredCount, fileCount=fileCount, duplicateCount=duplicateCount, duplicateHtml=duplicateHtml, searchHtml=searchHtml, hideIgnored=hideIgnored)

def processRawFiles(mediaItems):
  files = {}
  for item in mediaItems:
    fileName = item['filename']
    fileBaseName = os.path.splitext(fileName)[0]
    fileEnding = os.path.splitext(fileName)[1].lower()

    # match by file base name
    if fileBaseName in files:
      files[fileBaseName]['ids'].add(item['id'])
      files[fileBaseName]['endings'].add(fileEnding)      
      continue
    
    # new file
    files[fileBaseName] = {
      'ids': set([item['id']]),
      'endings': set([fileEnding])
    }
  return files

def findDuplicates(files):
  duplicates = []
  for filename in files:
    if len(files[filename]['ids']) > 1:
      duplicates.append(filename)
  duplicates.sort()
  return duplicates

@app.route('/duplicatePhotos/search/<fileName>')
def search(fileName = ""):
  global redirect
  global searchTerm

  print('entering search')

  if fileName == "":
    return flask.url_for('findDuplicatePhotos')
  processFileNameClick(fileName)

  searchTerm = fileName if searchTerm == "" else searchTerm
  message = ""
  if 'credentialsSearch' not in flask.session:
    print('couldnt find credentialsSearch')
    pprint(flask.session)
    redirect = 'search'
    return flask.redirect('authorize')

  credentials = google.oauth2.credentials.Credentials(**flask.session['credentialsSearch'])
  session = AuthorizedSession(credentials)
    
  return searchForFiles(session)

def processFileNameClick(fileName = ""):
  if not visitedFilesFileName or fileName == "":
    return

  with open(visitedFilesFileName, 'a') as f:
    f.write(f"{fileName}\n")
    f.close()

def searchForFiles(session):
  global searchTerm
  global fileCount
  global duplicateCount
  global duplicateHtml
  global searchHtml
  global message
  if not outputFileName or not os.path.isfile(outputFileName):
    return flask.render_template('data.html', duplicateCount=duplicateCount, fileCount=fileCount, duplicateHtml=duplicateHtml, searchMessage='Missing output file. Click "Hard Refresh" to recreate it.')

  print('Loaded file names from existing output')
  rawFiles = []
  with open(outputFileName, 'r') as f:
      rawFiles = json.loads(f.read().replace('\n', ''))
      f.close()
  
  fileNames = processRawFiles(rawFiles)
  fileName = fileNames[searchTerm] if searchTerm in fileNames else None

  items = []
  isError = False
  if fileName:
    fileIds = set(fileName['ids'])
    if fileIds and len(fileIds) > 0:
      requestUrl = "https://photoslibrary.googleapis.com/v1/mediaItems:batchGet?"
      for id in fileIds:
        requestUrl += f"&mediaItemIds={id}"
      requestUrl.replace("?&", "?")

      try:
        mediaResponse = session.get(requestUrl).json()
      except:
        message = f"Error with Google request: {sys.exc_info()[0]}"
        return flask.redirect('/')

      if 'mediaItemResults' not in mediaResponse:
        isError = True
        if 'error' in mediaResponse:
          message=f"There was a problem with the request: {mediaResponse['error']['message']}"
        else:
          print(mediaResponse)
          message="There was a problem with the request. See log for details."
      else:
        items = mediaResponse['mediaItemResults']
  
  ignoredFiles = []
  if ignoredFilesFileName and os.path.isfile(ignoredFilesFileName):
    with open(ignoredFilesFileName, 'r') as f:
      ignoredFiles = f.read().split('\n')
      f.close()
  isIgnored = fileName and fileName in ignoredFiles

  output = f"<br/>Results for files with the name '{searchTerm}' (<a href='https://photos.google.com/u/1/search/{searchTerm}' target='_blank'>Search term directly in Google Photos</a>): <a href='/duplicatePhotos/ignoreFile/{searchTerm}' style='margin-left:10px;'>Ignore</a> <a href='/duplicatePhotos/unignoreFile/{searchTerm}' style='margin-left:10px;'>Unignore</a><br/><ul>"
  if isError:
    output += f"<li>{message}</li>"
  else:
    if len(items) == 0:
      output += "<li>No files found</li>"
    for item in items:
      if 'mediaItem' not in item:
        output += "<li>Stale ID detected. File probably doesn't exist anymore. <a href='/refreshDuplicatePhotos'>Hard Refresh</a> is recommended to populate a fresh list of available media.</li>"
        break
      mediaItem = item['mediaItem']
      output += f"<li>{mediaItem['filename']}<ul><li>Created date: {mediaItem['mediaMetadata']['creationTime']}</li><li><a href={mediaItem['productUrl']} target='_blank'>Media Url</a></li><li>Media ID: <small>{mediaItem['id']}</small></li></ul>"
  output += "</ul>"
  searchHtml = output
  searchTerm = ""
  return flask.redirect("../../duplicatePhotos")

@app.route('/duplicatePhotos/ignoreFile/<fileName>')
def ignoreFile(fileName = ""):
  global ignoredFilesFileName
  if not ignoredFilesFileName or fileName == "":
    return flask.redirect(flask.url_for('findDuplicatePhotos'))

  with open(ignoredFilesFileName, 'a') as f:
    f.write(f"{fileName}\n")
    f.close()
  return flask.redirect(flask.url_for('findDuplicatePhotos'))

@app.route('/duplicatePhotos/unignoreFile/<fileName>')
def unignoreFile(fileName = ""):
  global ignoredFilesFileName
  if not ignoredFilesFileName or fileName == "":
    return flask.redirect(flask.url_for('findDuplicatePhotos'))

  with open(ignoredFilesFileName, "r") as f:
    lines = f.readlines()
  with open(ignoredFilesFileName, "w") as f:
    for line in lines:
      if line.strip("\n") != fileName:
        f.write(line)
    f.close()
  return flask.redirect(flask.url_for('findDuplicatePhotos'))

@app.route('/refreshDuplicatePhotos')
def refreshDuplicatePhotos():
  global forceRefresh
  global redirect
  forceRefresh = True
  redirect = 'duplicate'
  return flask.redirect('authorize')

@app.route('/clearVisitedCache')
def clearVisitedCache():
  global visitedFilesFileName
  if visitedFilesFileName and os.path.isfile(visitedFilesFileName):
    os.remove(visitedFilesFileName)
  return flask.redirect('duplicatePhotos')

@app.route('/clearIgnored')
def clearIgnoredCache():
  global ignoredFilesFileName
  if ignoredFilesFileName and os.path.isfile(ignoredFilesFileName):
    os.remove(ignoredFilesFileName)
  return flask.redirect('duplicatePhotos')

@app.route('/clearCache')
def clearCache():
  global message
  global visitedFilesFileName
  global outputFileName
  if visitedFilesFileName and os.path.isfile(visitedFilesFileName):
    os.remove(visitedFilesFileName)
  if outputFileName and os.path.isfile(outputFileName):
    os.remove(outputFileName)
    message = "Saved data cleared"
  else:
    message = "No saved data to clear"
  return flask.redirect('/')

@app.route('/authorize')
def authorize():
  if not CLIENT_SECRETS_FILE or not os.path.isfile(CLIENT_SECRETS_FILE):
    return flask.render_template('index.html', message="Missing client secret file for Google API!")
  with open(CLIENT_SECRETS_FILE, 'r') as f:
    if len(f.read()) == 0:
      return flask.render_template('index.html', message="Client secret file for Google API is empty!")
    f.close()

  # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)

  # The URI created here must exactly match one of the authorized redirect URIs
  # for the OAuth 2.0 client, which you configured in the API Console. If this
  # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
  # error.
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  authorization_url, state = flow.authorization_url(
      # Enable offline access so that you can refresh an access token without
      # re-prompting the user for permission. Recommended for web server apps.
      access_type='offline',
      # Enable incremental authorization. Recommended as a best practice.
      include_granted_scopes='true')

  # Store the state so the callback can verify the auth server response.
  flask.session['state'] = state

  return flask.redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
  global message
  global redirect
  # Specify the state when creating the flow in the callback so that it can
  # verified in the authorization server response.
  state = flask.session['state']

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)

  # Store credentials in the session.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  credentials = flow.credentials
  currentRedirect = redirect
  redirect = ""
  message = "Credentials set"
  if currentRedirect == 'duplicate':
    flask.session['credentials'] = credentials_to_dict(credentials)
    return flask.redirect(flask.url_for('findDuplicatePhotos'))
  if currentRedirect == 'search':
    flask.session['credentialsSearch'] = credentials_to_dict(credentials)
    return flask.redirect(flask.url_for('search'))

  flask.session['credentials'] = credentials_to_dict(credentials)
  flask.session['credentialsSearch'] = credentials_to_dict(credentials)
  return flask.redirect('/')


@app.route('/reset')
def reset():
  global message
  foundCreds = False
  revoke = None
  errorOccurred = False
  reason = ""
  if 'credentials' in flask.session:
    foundCreds = True
    credentials = google.oauth2.credentials.Credentials(
      **flask.session['credentials'])
    revoke = requests.post('https://oauth2.googleapis.com/revoke',
        params={'token': credentials.token},
        headers = {'content-type': 'application/x-www-form-urlencoded'})
    status_code = getattr(revoke, 'status_code')
    if status_code != 200:
      reason = getattr(revoke, 'content')
      print(f"{status_code}: {reason}")
      errorOccurred=True
    del flask.session['credentials']

  if 'credentialsSearch' in flask.session:
    foundCreds = True
    credentials = google.oauth2.credentials.Credentials(
      **flask.session['credentialsSearch'])
    revoke = requests.post('https://oauth2.googleapis.com/revoke',
        params={'token': credentials.token},
        headers = {'content-type': 'application/x-www-form-urlencoded'})
    status_code = getattr(revoke, 'status_code')
    if status_code != 200:
      reason = getattr(revoke, 'content')
      print(f"{status_code}: {reason}")
      errorOccurred=True
    del flask.session['credentialsSearch']

  if foundCreds:
    if errorOccurred and not b'Token expired or revoked' in reason:
      message=f'An error occurred during credential revocation: {reason}'
    else:
      message='Credentials successfully reset.'
  else:
    message='No credentials to revoke'
  return flask.redirect('/')

def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

if __name__ == '__main__':
  # When running locally, disable OAuthlib's HTTPs verification.
  # ACTION ITEM for developers:
  #     When running in production *do not* leave this option enabled.
  os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
  os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

  # Specify a hostname and port that are set as a valid redirect URI
  # for your API project in the Google API Console.
  app.run('localhost', 8080, debug=True)