import os
from flask import Flask, render_template, request, redirect, url_for, session, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Use local PostgreSQL or environment variable DATABASE_URL
POSTGRES_LOCAL_URI = 'postgresql://manju:password@localhost/postgres'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or POSTGRES_LOCAL_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    counter_id = db.Column(db.Integer, db.ForeignKey('counter.id'), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Counter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    items = db.relationship('Item', backref='counter', lazy=True)
    user = db.relationship('User', backref='counter', uselist=False)
    people_served = db.Column(db.Integer, default=0)  # Track people who have consumed

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    total_quantity = db.Column(db.Integer, nullable=False)
    consumed_quantity = db.Column(db.Integer, default=0)
    counter_id = db.Column(db.Integer, db.ForeignKey('counter.id'), nullable=False)

# Decorator to protect admin routes
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Routes

@app.route('/')
def home():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if not user:
            return redirect(url_for('login'))
        if user.is_admin:
            return redirect(url_for('admin_dashboard'))
        counter = user.counter
        items = counter.items
        remaining_food = sum(item.total_quantity - item.consumed_quantity for item in items)
        initial_people = 50
        people_served_items = sum(item.consumed_quantity for item in items)
        people_left = max(initial_people - people_served_items, 0)
        return render_template('dashboard.html', counter=counter, items=items,
                               remaining_food=remaining_food, people_left=people_left)
    return redirect(url_for('login'))

@app.route('/add_item', methods=['GET', 'POST'])
def add_item():
    if 'user_id' not in session or session.get('is_admin'):
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        name = request.form['item_name'].strip()
        total_qty = request.form['total_quantity']
        if name and total_qty.isdigit() and int(total_qty) > 0:
            new_item = Item(name=name, total_quantity=int(total_qty), counter=user.counter)
            db.session.add(new_item)
            db.session.commit()
            return redirect(url_for('home'))
    return render_template('add_item.html')

@app.route('/delete_item/<int:item_id>', methods=['POST'])
def delete_item(item_id):
    if 'user_id' not in session or session.get('is_admin'):
        return redirect(url_for('login'))
    item = Item.query.get_or_404(item_id)
    user = User.query.get(session['user_id'])
    if item.counter_id != user.counter_id:
        return "Forbidden", 403
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/update_item/<int:item_id>', methods=['POST'])
def update_item(item_id):
    if 'user_id' not in session or session.get('is_admin'):
        return redirect(url_for('login'))
    item = Item.query.get(item_id)
    if not item:
        return 'Item not found', 404
    try:
        consumed = int(request.form['consumed_quantity'])
    except ValueError:
        return 'Invalid quantity', 400
    if consumed < 0 or consumed > item.total_quantity:
        return 'Invalid quantity range', 400
    user = User.query.get(session['user_id'])
    if item.counter_id != user.counter_id:
        return "Forbidden", 403
    item.consumed_quantity = consumed
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/increment_people_served', methods=['POST'])
def increment_people_served():
    if 'user_id' not in session or session.get('is_admin'):
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    user.counter.people_served += 1
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('home'))
        else:
            return 'Invalid Credentials'
    return render_template('login.html')

@app.route('/logout', endpoint='logout')
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)
    return redirect(url_for('login'))

@app.route('/admin')
@admin_required
def admin_dashboard():
    counters = Counter.query.all()
    users = User.query.filter_by(is_admin=False).all()
    low_stock_threshold = 10
    low_stock_info = []
    for counter in counters:
        low_items = [item for item in counter.items if (item.total_quantity - item.consumed_quantity) <= low_stock_threshold]
        low_stock_info.append({'counter': counter, 'low_items': low_items})
    return render_template('admin_dashboard.html', counters=counters, users=users, low_stock_info=low_stock_info)

@app.route('/admin/data')
@admin_required
def admin_data():
    counters = Counter.query.all()
    users = User.query.filter_by(is_admin=False).all()
    low_stock_threshold = 10

    counters_data = []
    total_devotees_served = 0
    for counter in counters:
        low_items = [{
            'id': item.id,
            'name': item.name,
            'remaining': item.total_quantity - item.consumed_quantity
        } for item in counter.items if (item.total_quantity - item.consumed_quantity) <= low_stock_threshold]
        counters_data.append({
            'id': counter.id,
            'name': counter.name,
            'people_served': counter.people_served,
            'items_count': len(counter.items),
            'low_items': low_items
        })
        total_devotees_served += counter.people_served

    users_data = [{
        'id': user.id,
        'username': user.username,
        'counter_name': user.counter.name if user.counter else ''
    } for user in users]

    return jsonify({
        'counters': counters_data,
        'users': users_data,
        'total_devotees_served': total_devotees_served
    })

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    if session.get('user_id') == user_id:
        return "Cannot delete the currently logged-in user.", 403
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        return "Cannot delete admin user", 403
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_counter/<int:counter_id>', methods=['POST'])
@admin_required
def delete_counter(counter_id):
    counter = Counter.query.get_or_404(counter_id)
    if counter.items:
        for item in counter.items:
            db.session.delete(item)
    if counter.user:
        db.session.delete(counter.user)
    db.session.delete(counter)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/create_counter', methods=['GET', 'POST'])
@admin_required
def create_counter():
    if request.method == 'POST':
        name = request.form['name'].strip()
        if name:
            new_counter = Counter(name=name)
            db.session.add(new_counter)
            db.session.commit()
            return redirect(url_for('admin_dashboard'))
    return render_template('create_counter.html')

@app.route('/admin/create_user', methods=['GET', 'POST'])
@admin_required
def create_user():
    counters = Counter.query.all()
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        counter_id = request.form['counter_id']
        if username and password and counter_id:
            if User.query.filter_by(username=username).first():
                return 'Username already exists', 400
            user = User(username=username, counter_id=counter_id)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('admin_dashboard'))
    return render_template('create_user.html', counters=counters)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Seed initial data if not exists
        if not Counter.query.first():
            c1 = Counter(name='Counter 1')
            c2 = Counter(name='Counter 2')
            db.session.add_all([c1, c2])
            db.session.commit()

            items_c1 = [Item(name='Item A', total_quantity=100, counter=c1),
                        Item(name='Item B', total_quantity=80, counter=c1)]
            items_c2 = [Item(name='Item C', total_quantity=120, counter=c2),
                        Item(name='Item D', total_quantity=90, counter=c2)]
            db.session.add_all(items_c1 + items_c2)
            db.session.commit()

            u1 = User(username='volunteer1', counter=c1)
            u1.set_password('password1')
            u2 = User(username='volunteer2', counter=c2)
            u2.set_password('password2')
            db.session.add_all([u1, u2])
            db.session.commit()

        if not User.query.filter_by(is_admin=True).first():
            admin = User(username='admin', is_admin=True)
            admin.set_password('adminpass')
            db.session.add(admin)
            db.session.commit()

    app.run(debug=True)
