from flask import Flask, request, jsonify
from flask_mongoengine import MongoEngine
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['MONGODB_SETTINGS'] = {'db': 'restapi', 'host': 'localhost', 'port': 27017}
app.config['SECRET_KEY'] = 'secret'
db = MongoEngine()
db.init_app(app)

class User(db.Document):
    username = db.StringField(required=True, unique=True)
    password = db.StringField(required=True)
    is_admin = db.BooleanField(default=False)  # Ajout du rôle admin

class Order(db.Document):
    product = db.StringField(required=True)
    quantity = db.IntField(required=True)
    user_id = db.ReferenceField(User, required=True)  # Lien avec l'utilisateur


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.objects.get(id=data['id'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.get_json()
    user = User.objects(username=data['username']).first()
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Authentication failed'}), 401
    token = jwt.encode({'id': str(user.id), 'is_admin': user.is_admin, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm='HS256')
    return jsonify({'token': token})

@app.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    user = User(username=data['username'], password=hashed_password, is_admin=data.get('is_admin', False))
    user.save()
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/users', methods=['GET'])
@token_required
def get_users(current_user):
    if not current_user.is_admin:
        return jsonify({'message': 'Unauthorized'}), 403
    users = User.objects()
    return jsonify(users), 200

@app.route('/users/<id>', methods=['DELETE'])
@token_required
def delete_user(current_user, id):
    if not current_user.is_admin:
        return jsonify({'message': 'Unauthorized'}), 403
    User.objects(id=id).delete()
    return '', 204

@app.route('/orders', methods=['POST'])
@token_required
def create_order(current_user):
    data = request.get_json()
    order = Order(
        product=data['product'],
        quantity=data['quantity'],
        user_id=current_user  # L'utilisateur qui a créé la commande
    )
    order.save()
    return jsonify({
        'id': str(order.id),
        'product': order.product,
        'quantity': order.quantity,
        'user': str(current_user.id)  # Renvoie l'ID de l'utilisateur
    }), 201

@app.route('/orders', methods=['GET'])
@token_required
def get_orders(current_user):
    if current_user.is_admin:
        orders = Order.objects()
    else:
        orders = Order.objects(user_id=current_user)  # Un utilisateur voit seulement ses commandes
    orders_list = []
    for order in orders:
        orders_list.append({
            'id': str(order.id),
            'product': order.product,
            'quantity': order.quantity,
            'user': {
                'id': str(order.user_id.id) if order.user_id else None,
                'username': order.user_id.username if order.user_id else 'Unknown'
            }
        })
    return jsonify(orders_list), 200

@app.route('/orders/<id>', methods=['DELETE'])
@token_required
def delete_order(current_user, id):
    if current_user.is_admin:
        order = Order.objects(id=id).first()
    else:
        order = Order.objects(id=id, user_id=current_user).first()
    if not order:
        return jsonify({'message': 'Order not found or unauthorized'}), 403
    order.delete()
    return '', 204

if __name__ == '__main__':
    app.run(debug=True, port=3000)
