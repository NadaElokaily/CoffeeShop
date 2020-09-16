import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)
# CORS(app,resources={r"/": {"origins": "*"}})
# https://coffeeshopxx.us.auth0.com/u/login?state=g6Fo2SB0NnVZRW8zSTZQaFFNTngzN0g1dVlqVjhpVmt2d0x4N6N0aWTZIGFCRUxZeV9IU25zR1lxQkdwNkdnQl9WYks0eXlkZ0I0o2NpZNkgNkMxOEEzN1ZYaml6VVcxcU9qUnBudkFUc25LOHRVNTE
@app.after_request
def after_request(response):
    response.headers.add(
        'Access-Control-Allow-Headers',
        'Content-Type,Authorization,true')
    response.headers.add(
        'Access-Control-Allow-Methods',
        'GET,PATCH,POST,DELETE,OPTIONS')
    return response

'''
@DONE uncomment the following line to initialize the datbase
!! NOTE THIS WILL DROP ALL RECORDS AND START YOUR DB FROM SCRATCH
!! NOTE THIS MUST BE UNCOMMENTED ON FIRST RUN
'''
# db_drop_and_create_all()

## ROUTES
'''
@DONE implement endpoint
    GET /drinks
        ////it should be a public endpoint
        it should contain only the drink.short() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''
@app.route('/',methods=['GET'])
def index():
    return "<h1>HELLO</h1>"

@app.route('/logout',methods=['GET'])
def logout():
    # session.clear()
    # params = {'returnTo': url_for('home', _external=True), 'client_id': '6C18A37VXjizUW1qOjRpnvATsnK8tU51'}
    # return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))
    return "<h1>BYE</h1>"

@app.route('/drinks',methods=['GET'])
def get_drinks():
    try:
        if request.method == "GET":
            drinks = Drink.query.all()
            return jsonify({
                'success':True,
                'drinks':[drink.short() for drink in drinks]
            }),200
    except Exception:
        abort(422)

'''
@DONE implement endpoint
    GET /drinks-detail
        ////it should require the 'get:drinks-detail' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''
@app.route('/drinks-detail',methods=['GET'])
@requires_auth('get:drinks-detail')
def get_drinks_detail(payload):
    try:
        drinks = Drink.query.all()
        return jsonify({
            'success':True,
            'drinks':[drink.long() for drink in drinks]
        }),200
    except Exception:
        abort(422)


'''
@TODO implement endpoint
    POST /drinks
        it should create a new row in the drinks table
        ////it should require the 'post:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the newly created drink
        or appropriate status code indicating reason for failure
'''
@app.route('/drinks',methods=['POST'])
@requires_auth('post:drinks')
def post_drinks(payload):
    try:
        drink_info = request.get_json()
        if drink_info == None:
            abort(404)
        if type(drink_info['recipe']) is dict:
            drink_info['recipe'] = [drink_info['recipe']]
        d = Drink(title = drink_info['title'],recipe = json.dumps(drink_info['recipe']))
        d.insert()
        return jsonify({
            'success':True,
            'drinks':d.long()
        }),200
    except Exception:
        abort(422)


'''
@DONE implement endpoint
    PATCH /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should update the corresponding row for <id>
        it should require the 'patch:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the updated drink
        or appropriate status code indicating reason for failure
'''
@app.route('/drinks/<int:id>',methods=['PATCH'])
@requires_auth('patch:drinks')
def patch_drinks(payload,id):
    try:
        drink = Drink.query.filter(Drink.id==id).one_or_none()
        if drink is None:
            abort(404)
        new_drink = request.get_json()
        if 'title' in new_drink:
            drink.title = new_drink['title']
        if 'recipe' in new_drink:
            drink.recipe = json.dumps(new_drink['recipe'])
        drink.update()
        return jsonify({
            'success':True,
            'drinks':[drink.long()]
        }),200
    
    except Exception:
        abort(422)



'''
@DONE implement endpoint
    DELETE /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should delete the corresponding row for <id>
        it should require the 'delete:drinks' permission
    returns status code 200 and json {"success": True, "delete": id} where id is the id of the deleted record
        or appropriate status code indicating reason for failure
'''
@app.route('/drinks/<int:id>',methods=['DELETE'])
@requires_auth('delete:drinks')
def delete_drinks(payload,id):
    try:
        drink = Drink.query.filter(Drink.id == id).one_or_none()
        if drink is None:
            abort(404)
        drink.delete()
        return jsonify({
            "success":True,
            "delete":id
        }),200
    except Exception:
        abort(422)

## Error Handling
'''
Example error handling for unprocessable entity
'''
@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False, 
        "error": 422,
        "message": "unprocessable"
        }), 422

'''
@DONE implement error handlers using the @app.errorhandler(error) decorator
    each error handler should return (with approprate messages):
             jsonify({
                    "success": False, 
                    "error": 404,
                    "message": "resource not found"
                    }), 404

'''
@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({
        "success":False,
        "error":500,
        "message":"Internal Server Error"
        }),500

@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        "success":False,
        "error":400,
        "message":"Bad Request"
        }),400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({
        "success":False,
        "error":401,
        "message":"Unauthorized"
        }),401

@app.errorhandler(403)
def forbidden(error):
    return jsonify({
        "success":False,
        "error":403,
        "message":"Forbidden"
        }),403

'''
@DONE implement error handler for 404
    error handler should conform to general task above 
'''
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success":False,
        "error":404,
        "message":"Not Found"
        }),404


'''
@TODO implement error handler for AuthError
    error handler should conform to general task above 
'''
@app.errorhandler(AuthError)
def authentication_error(error):
    return jsonify({
        "success":False,
        "error":error.status_code,
        "message":error.error['description']
        }),error.status_code

