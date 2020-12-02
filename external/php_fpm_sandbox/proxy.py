#!/usr/bin/python3

from socket import AF_INET, SOCK_STREAM, socket
from flask import Flask, request
import os
import json
import random
import string
from enum import IntEnum
from flask.json import jsonify
import base64

from werkzeug.utils import secure_filename

NAME = 'fpm_sandbox_proxy'
LISTEN_PORT = os.environ.get('PROXY_LISTEN_PORT') if 'PROXY_LISTEN_PORT' in os.environ else 9001
SCRIPT_PATH = '/tmp/scripts'

class status(IntEnum):
  PENDING = 0
  DETECTED = 1

app = Flask(NAME)
results = {}
info = {}

@app.route('/', methods=['post'])
def new_execution():
  request_id = ''.join(random.sample(string.ascii_letters, 6))
  params = json.loads(request.form['params'])
  script = request.files['script']
  stdin = request.form['stdin'].encode()
  save_path = os.path.join(SCRIPT_PATH, request_id)
  os.makedirs(save_path, 755)
  script_path = os.path.join(save_path, secure_filename(script.filename))
  script.save(script_path)
  params['SCRIPT_FILENAME'] = script_path
  params['DOCUMENT_ROOT'] = save_path
  params['REQUEST_ID'] = request_id
  results[request_id] = status.PENDING
  info[request_id] = ''
  execute(params, stdin)
  detected = False
  if results[request_id] == status.DETECTED:
    detected = True
  return jsonify({ 'detected': detected, 'info': base64.b64encode(info[request_id].encode()) })

@app.route('/<request_id>', methods=['get'])
def detected(request_id):
  results[request_id] = status.DETECTED
  info[request_id] = request.args.get('info')
  return jsonify({ 'success': True })

class _fcgi_request_type(IntEnum):
  FCGI_BEGIN_REQUEST = 1
  FCGI_ABORT_REQUEST = 2
  FCGI_END_REQUEST = 3
  FCGI_PARAMS = 4
  FCGI_STDIN = 5
  FCGI_STDOUT = 6
  FCGI_STDERR = 7
  FCGI_DATA = 8
  FCGI_GET_VALUES = 9
  FCGI_GET_VALUES_RESULT = 10

def generate_fpm_packet(request_id, type, params = None, version = 1):
  content = b''
  if type == _fcgi_request_type.FCGI_BEGIN_REQUEST:
    content = b'\x00\x01\x00\x00\x00\x00\x00\x00'
  elif type == _fcgi_request_type.FCGI_PARAMS:
    for key, value in params.items():
      key = key.encode()
      value = value.encode()
      key_length = len(key)
      value_length = len(value)
      if key_length < 0x80:
        content += key_length.to_bytes(1, 'big')
      else:
        content += (key_length | 0x80000000).to_bytes(4, 'big')
      if value_length < 0x80:
        content += value_length.to_bytes(1, 'big')
      else:
        content += (value_length | 0x80000000).to_bytes(4, 'big')
      content += key + value
  elif type == _fcgi_request_type.FCGI_STDIN:
    content = params
  packet = b''
  while True:
    packet += version.to_bytes(1, 'big') + type.to_bytes(1, 'big') + request_id.to_bytes(2, 'big')
    if len(content) > 65535:
      current_content = content[:65535]
      content = content[65535:]
    else:
      current_content = content
      content = b''
    packet += len(current_content).to_bytes(2, 'big') + b'\x00\x00'
    packet += current_content
    if len(content) == 0:
      break
  return packet

def parse_header(raw):
  type = raw[1]
  contentLength = (raw[4] << 8) + raw[5]
  paddingLength = raw[6]
  return type, contentLength, paddingLength

def get_response(sock):
  header_raw = sock.recv(8)
  if header_raw == None:
    return None, None
  type, contentLength, paddingLength = parse_header(header_raw)
  content = b''
  if contentLength != 0:
    content = sock.recv(contentLength)
  if paddingLength != 0:
    sock.recv(paddingLength)
  return type, content

def execute(params, stdin):
  sock = socket(AF_INET, SOCK_STREAM)
  sock.connect(('127.0.0.1', 9000))
  sock.send(generate_fpm_packet(1, _fcgi_request_type.FCGI_BEGIN_REQUEST))
  sock.send(generate_fpm_packet(1, _fcgi_request_type.FCGI_PARAMS, params))
  sock.send(generate_fpm_packet(1, _fcgi_request_type.FCGI_STDIN, stdin))
  stdout = b''
  stderr = b''
  success = False
  while True:
    type, content = get_response(sock)
    if type == None:
      break
    if type == _fcgi_request_type.FCGI_STDOUT:
      stdout += content
    elif type == _fcgi_request_type.FCGI_STDERR:
      stderr += content
    elif type == _fcgi_request_type.FCGI_END_REQUEST:
      success = True
      break
  return success, stdout, stderr

if __name__ == '__main__':
  if not os.path.exists(SCRIPT_PATH):
    os.makedirs(SCRIPT_PATH, 755, True)
  app.run('0.0.0.0', LISTEN_PORT)
