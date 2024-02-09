from flask import Flask, request, jsonify
from datetime import datetime
import uuid 

from flask_jwt_extended import JWTManager, jwt_required, create_access_token, current_user
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'super-secret'
jwt = JWTManager(app)


# model
class TodoItem:
  def __init__(self, id, item_name, created_time_stamp, updated_time_stamp):
    self.id = id 
    self.item_name = item_name 
    self.created_time_stamp = created_time_stamp
    self.updated_time_stamp = updated_time_stamp

class UserProfile:
  def __init__(self, username, password):
    self.username = username 
    self.password = password 
    self.todoItem = dict()



# structures
todoMap = {}

users = {
  "user1@abc.com":UserProfile("user1@abc.com", "password1"),
  "user2@abc.com":UserProfile("user2@abc.com", "password2"),
}

# helpers
def get_user_profile(request_json):
  username = request_json['username']
  password = request_json['password']
  if username not in users:
    return None, "Invalid credentials, requested user not found"

  if users[username].username == username and \
    users[username].password == password:
    return users[username], ""



# handlers
@app.route('/')
def hello():
  return 'hello world'

@app.route('/signin', methods=["POST"])
def Signin():
  request_json = request.get_json()
  user, error = get_user_profile(request_json)
  if user:
    access_token = create_access_token(identity=user.username)
    return {
      "Msg": "Success",
      "Status": 200,
      "User": user.username,
      "access_token": access_token
    }
  else:
    return {
      "Msg": error,
      "Status": 401,
    }
    

@app.route('/refresh', methods=["POST"])
def Refresh():
  pass 

@app.route('/create', methods=["POST"])
@jwt_required()
def Create():
  request_json = request.get_json()
  item_name = request_json['item_name']
  uu_id = uuid.uuid4().hex
  create_time = datetime.now().ctime()
  todoMap[uu_id] = TodoItem(uu_id, item_name, create_time, create_time)
  users[current_user].todoItem[uu_id]=uu_id

  return {
      "Msg": "Success",
      "Status": 201,
  }

@app.route('/update', methods=["POST"])
@jwt_required()
def Update():
  request_json = request.get_json()
  item_id = request_json['item_id']
  item_name = request_json['item_name']

  # search and update 
  for uuid, _ in todoMap.items():
    if uuid == item_id:
      todoMap[uuid].item_name = item_name
      todoMap[uuid].update_time_stamp = datetime.now().ctime()
      return {
        "Msg": "Success",
        "Status": 200,
      } 
  return {
      "Error": "Bad request check payload",
      "Status": 401,
  } 

@app.route('/delete', methods=["POST"])
@jwt_required()
def Delete():
  user_profile = users[current_user]
  todo_user_map = user_profile.todoItem

  request_json = request.get_json()

  item_id = request_json['item_id']
  todo_user_map.pop(item_id, None)
  todoMap.pop(item_id, None)

  return {
    "Msg": "Success",
    "Status": 200,
  }


@jwt.user_lookup_loader
def user_lookup_callback(jwt_header, jwt_data):
  identity = jwt_data["sub"]
  return identity

@app.route('/list', methods=["GET"])
@jwt_required()
def List():
  user_profile = users[current_user]
  todo_list = user_profile.todoItem
  items = []
  for id in todo_list:
    todo_item = todoMap[id]
    items.append({
      "id": todo_item.id,
      "item_name": todo_item.item_name,
      "created_time_stamp": todo_item.created_time_stamp,
      "updated_time_stamp": todo_item.updated_time_stamp
    })
    
  return {
    "Msg": "Success",
    "Status": 200,
    "Items": items
  }
