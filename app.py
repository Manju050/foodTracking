import os
from flask import Flask, render_template, request, redirect, url_for, session, abort, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from io import StringIO
import csv
from datetime import datetime
from io import BytesIO

app = Flask(__name__)
app.secret_key = 'supersecretkey'

POSTGRES_LOCAL_URI = 'postgresql://manju-17840:password@localhost/postgres'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or POSTGRES_LOCAL_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# Models
class InitialPreparedSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_name = db.Column(db.String(100), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=False)

    # Relationship with cascade delete-orphan
    items = db.relationship(
        'InitialPreparedItem',
        backref='session',
        lazy=True,
        cascade="all, delete-orphan"
    )

class InitialPreparedItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('initial_prepared_session.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    total_prepared = db.Column(db.Integer, nullable=False)

class CounterItemStock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(100), nullable=False)

    counter_id = db.Column(db.Integer, db.ForeignKey('counter.id'), nullable=False)
    session_id = db.Column(db.Integer, db.ForeignKey('initial_prepared_session.id'), nullable=False)
    available_stock = db.Column(db.Integer, default=0)
    counter = db.relationship('Counter', backref='counter_item_stocks')
    session = db.relationship('InitialPreparedSession', backref='counter_item_stocks')

    __table_args__ = (
        db.UniqueConstraint('item_name', 'counter_id', 'session_id', name='uq_item_counter_session'),
    )


from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    counters = db.relationship('Counter', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Counter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # ForeignKey to user


class GlobalStats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    total_devotees_taken = db.Column(db.Integer, default=0)


class FeedingSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    data = db.Column(db.Text, nullable=False)  # CSV string storing session data


# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def sync_session_items_to_counters(session_id):
    session = InitialPreparedSession.query.get(session_id)
    if not session:
        return
    counters = Counter.query.all()
    session_item_names = {item.name for item in session.items}

    for counter in counters:
        # Existing counter items for this session
        existing_counter_items = CounterItemStock.query.filter_by(counter_id=counter.id, session_id=session_id).all()
        existing_names = {citem.item_name for citem in existing_counter_items}

        # Add new items missing on counter
        for ip_item in session.items:
            if ip_item.name not in existing_names:
                new_stock = CounterItemStock(
                    item_name=ip_item.name,
                    counter_id=counter.id,
                    session_id=session_id,
                    available_stock=0,
                )
                db.session.add(new_stock)

        # Update total_prepared for existing counter items matching session items
        for c_item in existing_counter_items:
            session_item = next((i for i in session.items if i.name == c_item.item_name), None)
            if session_item:
                pass
            else:
                # Remove item from counter if session item deleted
                db.session.delete(c_item)

    db.session.commit()

@app.route('/admin/activate_session/<int:session_id>', methods=['POST'])
@admin_required
def activate_session(session_id):
    # Deactivate all
    InitialPreparedSession.query.update({InitialPreparedSession.is_active: False})
    # Activate selected
    session_to_activate = InitialPreparedSession.query.get_or_404(session_id)
    session_to_activate.is_active = True
    db.session.commit()
    sync_session_items_to_counters(session_to_activate.id)

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/deactivate_session/<int:session_id>', methods=['POST'])
@admin_required
def deactivate_session(session_id):
    session_to_deactivate = InitialPreparedSession.query.get_or_404(session_id)
    session_to_deactivate.is_active = False
    db.session.commit()
    flash(f'Session "{session_to_deactivate.session_name}" deactivated successfully!', 'info')
    return redirect(url_for('admin_dashboard'))

def volunteer_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = db.session.get(User, session['user_id'])
        if not user or user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/counter_dashboard', methods=['GET', 'POST'])
@login_required
def counter_dashboard():
    user = get_current_user()
    counters = user.counters  # List of user's counters

    counter_id = request.args.get('counter_id') or request.form.get('counter_id')
    counter = None
    items = []

    if counter_id:
        counter = Counter.query.filter(Counter.id == counter_id, Counter.user_id == user.id).first()
        if not counter:
            flash("Counter not found or not owned by you.", "danger")
            return redirect(url_for('counter_dashboard'))

        if request.method == 'POST':
            # process updated available stock per item
            for item in counter.items:
                field_name = f"available_stock_{item.id}"
                if field_name in request.form:
                    try:
                        new_stock = int(request.form[field_name])
                        item.available_stock = new_stock
                    except ValueError:
                        continue
            db.session.commit()
            flash("Available stock updated.", "success")
            return redirect(url_for('counter_dashboard', counter_id=counter.id))

        items = counter.items  # preload items of selected counter

    return render_template('counter_dashboard.html',
                           counters=counters,
                           counter=counter,
                           items=items)


@app.route('/update_available_stock/<int:counter_id>/<int:session_id>', methods=['POST'])
@volunteer_required
def update_available_stock(counter_id, session_id):
    counter = Counter.query.get_or_404(counter_id)
    session_obj = InitialPreparedSession.query.get_or_404(session_id)
    user = db.session.get(User, session['user_id'])
    if counter.user_id != user.id:
        return "Forbidden", 403

    for stock_entry in CounterItemStock.query.filter_by(counter_id=counter_id, session_id=session_id):
        form_field = f"available_stock_{stock_entry.id}"
        if form_field in request.form:
            try:
                val = int(request.form[form_field])
                stock_entry.available_stock = val
            except ValueError:
                pass

    db.session.commit()
    return redirect(url_for('home', counter_id=counter_id))


@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    user = db.session.get(User, session['user_id'])
    if user.is_admin:
        return redirect(url_for('admin_dashboard'))

    user_counters = user.counters
    if not user_counters:
        return "No counters assigned to this user.", 400

    counter_id = request.args.get('counter_id', type=int)
    counter = None

    if counter_id:
        counter = next((c for c in user_counters if c.id == counter_id), None)
        if not counter:
            flash("Selected counter not found or unauthorized", "danger")
            counter = user_counters[0]
    else:
        counter = user_counters[0]

    active_session = InitialPreparedSession.query.filter_by(is_active=True).first()
    items = []

    items = []
    if active_session:
        items = CounterItemStock.query.filter_by(
            counter_id=counter.id,
            session_id=active_session.id
        ).all()
    
    no_active_session = active_session is None

    return render_template('dashboard.html',
                           counters=user_counters,
                           counter=counter,
                           items=items,
                           active_session=active_session,no_active_session=no_active_session)

@app.route('/admin/delete_session/<int:session_id>', methods=['POST'])
@admin_required
def delete_session(session_id):
    session_obj = InitialPreparedSession.query.get_or_404(session_id)
    
    # This cascades delete to InitialPreparedItem if cascade is set on relationship
    db.session.delete(session_obj)
    db.session.commit()
    
    flash(f'Session "{session_obj.session_name}" and all its items were deleted.', 'success')
    return redirect(url_for('initial_prepared'))


@app.route('/admin/initial_prepared', methods=['GET', 'POST'])
@admin_required
def initial_prepared():
    if request.method == 'POST':
        session_name = request.form.get('session_name', '').strip()
        item_names = request.form.getlist('item_name')
        total_prepareds = request.form.getlist('total_prepared')
        senior_taken_list = request.form.getlist('senior_taken')

        if not session_name:
            return "Session name is required", 400

        if InitialPreparedSession.query.filter_by(session_name=session_name).first():
            return "Session name already exists", 400

        # Create session
        new_session = InitialPreparedSession(session_name=session_name)
        db.session.add(new_session)
        db.session.flush()  # to get new_session.id

        # Add items
        for name, total in zip(item_names, total_prepareds):
            if name.strip() and total.isdigit():
                ip_item = InitialPreparedItem(
                    session_id=new_session.id,
                    name=name.strip(),
                    total_prepared=int(total),
                )
                db.session.add(ip_item)

        db.session.commit()
        # Sync session items to counters right after saving new session
        sync_session_items_to_counters(new_session.id)
        return redirect(url_for('initial_prepared'))

    # GET: Fetch sessions and active session to pass to template
    sessions = InitialPreparedSession.query.order_by(InitialPreparedSession.created_at.desc()).all()
    active_session = InitialPreparedSession.query.filter_by(is_active=True).first()

    return render_template('initial_prepared.html', 
                           sessions=sessions, 
                           active_session=active_session)

@app.route('/admin/update_total_devotees', methods=['POST'])
@admin_required
def update_total_devotees():
    total = request.form.get('total_devotees', '0')
    if total.isdigit():
        total_int = int(total)
        stats = GlobalStats.query.first()
        if not stats:
            stats = GlobalStats(total_devotees_taken=total_int)
            db.session.add(stats)
        else:
            stats.total_devotees_taken = total_int
        db.session.commit()
    return redirect(url_for('admin_dashboard'))



@app.route('/update_available/<int:item_id>', methods=['POST'])
@volunteer_required
def update_available(item_id):
    item = Item.query.get(item_id)
    user = db.session.get(User, session['user_id'])
    if not item or item.counter_id != user.counter_id:
        return "Forbidden", 403
    try:
        value = int(request.form['available_stock'])
    except ValueError:
        return 'Invalid value', 400
    item.available_stock = value
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin_dashboard():
    if request.method == 'POST':
        total_prepared_inputs = request.form.getlist('total_prepared')
        senior_taken_inputs = request.form.getlist('senior_taken')
        item_names = request.form.getlist('item_name_hidden')

        for idx, name in enumerate(item_names):
            ip_items = InitialPreparedItem.query.filter_by(name=name).all()
            T = int(total_prepared_inputs[idx]) if total_prepared_inputs[idx].isdigit() else 0
            S = int(senior_taken_inputs[idx]) if senior_taken_inputs[idx].isdigit() else 0
            for ip_item in ip_items:
                ip_item.total_prepared = T
                # You may extend InitialPreparedItem to store senior_taken if needed
            db.session.commit()
        return redirect(url_for('admin_dashboard'))

    counters = Counter.query.all()
    users = User.query.filter_by(is_admin=False).all()

    active_session = InitialPreparedSession.query.filter_by(is_active=True).first()
    if active_session:
        session_items = InitialPreparedItem.query.filter_by(session_id=active_session.id).all()
    else:
        session_items = []

    from sqlalchemy import func

    stock_agg = []
    stock_map = {}

    if active_session:
        # Aggregate only available_stock by item_name for the session
        stock_agg = db.session.query(
            CounterItemStock.item_name,
            func.coalesce(func.sum(CounterItemStock.available_stock), 0)
        ).filter(
            CounterItemStock.session_id == active_session.id
        ).group_by(
            CounterItemStock.item_name
        ).all()

        stock_map = {name: total for name, total in stock_agg}

    stats = GlobalStats.query.first()
    total_devotees_taken = stats.total_devotees_taken if stats else 0
    count = total_devotees_taken

    items_list = []

    for ip_item in session_items:
        name = ip_item.name
        T = ip_item.total_prepared
        S = 0  # senior_taken is zero by default; extend if tracked

        x = stock_map.get(name, 0)

        # Calculate consumed as total_prepared - available_stock - senior_taken
        consumed_calc = max(T - S - x, 0)

        denominator = T - S - x
        if denominator > 0 and count > 0:
            estimated_available = int(x * count / denominator)
        else:
            estimated_available = 0

        items_list.append({
            "name": name,
            "total_prepared": T,
            "senior_taken": S,
            "available_stock": x,
            "count": count,
            "estimated_available": estimated_available,
            "consumed": consumed_calc,    # Make sure this field is included
            "locked_total": True
        })


    sessions = InitialPreparedSession.query.order_by(InitialPreparedSession.created_at.desc()).all()

    return render_template('admin_dashboard.html', counters=counters, users=users,
                           items=items_list, initial_session=active_session, sessions=sessions)


from sqlalchemy import func

@app.route('/admin/api_data')
@admin_required
def admin_api_data():
    # Get current active session
    active_session = InitialPreparedSession.query.filter_by(is_active=True).first()
    if not active_session:
        # No active session, return empty data
        return jsonify({"items": [], "total_devotees_taken": 0})

    # Aggregate available_stock per item for the active session across all counters
    stock_sums = db.session.query(
        CounterItemStock.item_name,
        func.coalesce(func.sum(CounterItemStock.available_stock), 0)
    ).filter(
        CounterItemStock.session_id == active_session.id
    ).group_by(CounterItemStock.item_name).all()

    stock_sum_map = {name: total for name, total in stock_sums}

    # Get session items for total_prepared and senior_taken values
    session_items = InitialPreparedItem.query.filter_by(session_id=active_session.id).all()

    stats = GlobalStats.query.first()
    total_devotees_taken = stats.total_devotees_taken if stats else 0
    count = total_devotees_taken

    items_list = []
    for ip_item in session_items:
        name = ip_item.name
        T = ip_item.total_prepared
        S = 0  # Modify if you track senior_taken per session item, else keep 0
        x = stock_sum_map.get(name, 0)
        denominator = T - S - x
        consumed_calc = max(denominator, 0)
        print(f"{name}: T={T}, S={S}, x={x}, consumed={max(T - S - x, 0)}")

        if denominator > 0 and count > 0:
            estimated_available = int(x * count / denominator)
        else:
            estimated_available = 0

        items_list.append({
            "name": name,
            "total_prepared": T,
            "senior_taken": S,
            "available_stock": x,
            "estimated_available": estimated_available,
            "consumed": consumed_calc
        })

    return jsonify({
        "items": items_list,
        "total_devotees_taken": total_devotees_taken
    })


@app.route('/admin/manage_items', methods=['GET', 'POST'])
@admin_required
def manage_items():
    if request.method == 'POST':
        name = request.form['item_name'].strip()
        total = request.form['total_prepared']
        if name and total.isdigit():
            # Add or update global item totals here
            items = Item.query.filter_by(name=name).all()
            if not items:
                # Create one item with counter_id null or zero to hold total info (optional design)
                # or create items for all counters as needed
                pass
            else:
                for item in items:
                    item.total_prepared = int(total)
            db.session.commit()
            return redirect(url_for('manage_items'))

    # Show all unique item names with totals
    items_all = Item.query.all()
    items_dict = {}
    for i in items_all:
        if i.name not in items_dict:
            items_dict[i.name] = i.total_prepared

    return render_template('manage_items.html', items=items_dict)

@app.route('/admin/save_snapshot', methods=['POST'])
@admin_required
def save_snapshot():
    active_session = InitialPreparedSession.query.filter_by(is_active=True).first()
    if not active_session:
        # No active session, redirect or show error
        return redirect(url_for('admin_dashboard'))

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Item Name', 'Total Prepared', 'Senior Taken', 'Available Stock', 
                     'Consumed (T-S-x)', 'Devotees Taken (Count)', 'Estimated Available for Serving'])

    # Aggregate per item_name from CounterItemStock in active_session
    from sqlalchemy import func

    stock_agg = db.session.query(
        CounterItemStock.item_name,
        func.coalesce(func.sum(CounterItemStock.total_prepared), 0),
        func.coalesce(func.sum(CounterItemStock.available_stock), 0),
        func.coalesce(func.sum(CounterItemStock.consumed_quantity), 0)
    ).filter(
        CounterItemStock.session_id == active_session.id
    ).group_by(
        CounterItemStock.item_name
    ).all()

    stats = GlobalStats.query.first()
    total_devotees_taken = stats.total_devotees_taken if stats else 0

    for item_name, total_prepared, available_stock, consumed_quantity in stock_agg:
        S = 0  # senior_taken if tracked per session or zero
        T = total_prepared
        x = available_stock
        count = consumed_quantity

        consumed_calc = max(T - S - x, 0)
        denominator = max(T - S - x, 1)
        estimated_available = int(x * count / denominator) if denominator and count else x

        writer.writerow([item_name, T, S, x, consumed_calc, count, estimated_available])

    data_str = output.getvalue()
    snapshot = FeedingSession(data=data_str)
    db.session.add(snapshot)
    db.session.commit()

    return redirect(url_for('previous_sessions'))

@app.route('/admin/feeding_session_done', methods=['POST'])
@admin_required
def feeding_session_done():
    items = Item.query.all()
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Item Name', 'Total Prepared', 'Senior Taken', 'Available Stock', 'Consumed', 'Manual Consumed', 'Can Take'])

    items_dict = {}
    for item in items:
        key = item.name
        entry = items_dict.get(key)
        if not entry:
            entry = {
                "name": key,
                "available_stock": 0,
                "consumed_quantity": 0,
                "total_prepared": 0,
                "senior_taken": 0,
            }
            items_dict[key] = entry
        entry["available_stock"] += item.available_stock or 0
        entry["consumed_quantity"] += item.consumed_quantity or 0
        if item.total_prepared:
            entry["total_prepared"] = item.total_prepared
        if item.senior_taken:
            entry["senior_taken"] = item.senior_taken

    for itm in items_dict.values():
        T = itm["total_prepared"]
        S = itm["senior_taken"]
        x = itm["available_stock"]
        consumed_calc = max(T - S - x, 0)
        denominator = max(T - S, 1)
        consumption_rate = consumed_calc / denominator if denominator else 0
        possible_take = int(x * consumption_rate) if consumption_rate > 0 else x
        writer.writerow([itm["name"], T, S, x, consumed_calc, itm["consumed_quantity"], possible_take])

    data_str = output.getvalue()
    session_record = FeedingSession(data=data_str)
    db.session.add(session_record)
    db.session.commit()
    return redirect(url_for('previous_sessions'))


@app.route('/admin/previous_sessions')
@admin_required
def previous_sessions():
    sessions = FeedingSession.query.order_by(FeedingSession.timestamp.desc()).all()
    return render_template('previous_sessions.html', sessions=sessions)


@app.route('/admin/previous_sessions/download/<int:session_id>')
@admin_required
def download_feeding_session(session_id):
    session_record = FeedingSession.query.get_or_404(session_id)
    csv_data = session_record.data
    csv_bytes = csv_data.encode('utf-8')
    return send_file(
        BytesIO(csv_bytes),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'feeding_session_{session_record.timestamp.strftime("%Y%m%d_%H%M%S")}.csv'
)

@app.route('/select_session', methods=['GET', 'POST'])
@login_required
def select_session():
    sessions = InitialPreparedSession.query.order_by(InitialPreparedSession.created_at.desc()).all()
    if request.method == 'POST':
        selected_id = request.form.get('session_id')
        if selected_id and InitialPreparedSession.query.get(selected_id):
            session['selected_session_id'] = int(selected_id)
            return redirect(url_for('home'))
        else:
            return "Invalid session selected", 400
    return render_template('select_session.html', sessions=sessions)

@app.route('/admin/manage_session_items/<int:session_id>', methods=['GET', 'POST'])
@admin_required
def manage_session_items(session_id):
    session = InitialPreparedSession.query.get_or_404(session_id)
    if request.method == 'POST':
        submitted_ids = request.form.getlist('item_id')
        item_names = request.form.getlist('item_name')
        total_prepareds = request.form.getlist('total_prepared')

        # Fetch existing items from DB
        existing_items = InitialPreparedItem.query.filter_by(session_id=session.id).all()
        existing_ids = {str(item.id) for item in existing_items}

        # Determine which items to delete (existing but not submitted)
        ids_to_delete = existing_ids - set(submitted_ids)
        for del_id in ids_to_delete:
            InitialPreparedItem.query.filter_by(id=int(del_id)).delete()

        for idx, item_id in enumerate(submitted_ids):
            name = item_names[idx].strip()
            total = total_prepareds[idx].strip()
        
            if not name or not total.isdigit():
                continue
            
            total = int(total)
        
            if item_id:  # existing item, update it
                if item_id in existing_ids:
                    item = InitialPreparedItem.query.get(int(item_id))
                    item.name = name
                    item.total_prepared = total
            else:
                # New item (empty or missing id)
                item = InitialPreparedItem(session_id=session.id, name=name, total_prepared=total)
                db.session.add(item)


        db.session.commit()
        sync_session_items_to_counters(session.id)
        return redirect(url_for('initial_prepared'))

    # GET: provide session items to template
    items = InitialPreparedItem.query.filter_by(session_id=session.id).all()
    return render_template('manage_session_items.html', session=session, items=items)

@app.route('/admin/delete_session_item/<int:item_id>', methods=['POST'])
@admin_required
def delete_session_item(item_id):
    ip_item = InitialPreparedItem.query.get_or_404(item_id)
    session_id = ip_item.session_id
    db.session.delete(ip_item)
    db.session.commit()
    return redirect(url_for('manage_session_items', session_id=session_id))


@app.route('/admin/sync_items')
@admin_required
def admin_sync_items():
    sync_initial_items_to_counters()
    return redirect(url_for('admin_dashboard'))
from flask import flash

@app.route('/admin/manage_counters', methods=['GET', 'POST'])
@admin_required
def manage_counters():
    if request.method == 'POST':
        counter_name = request.form.get('counter_name', '').strip()
        username = request.form.get('username', '').strip()

        if not counter_name or not username:
            flash('Counter name and Username are required.', 'danger')
        else:
            user = User.query.filter_by(username=username).first()
            if not user:
                flash(f'User "{username}" does not exist.', 'danger')
            else:
                # Check if counter exists
                counter = Counter.query.filter_by(name=counter_name).first()
                if not counter:
                    # Create new counter and assign to user
                    counter = Counter(name=counter_name, user=user)
                    db.session.add(counter)
                else:
                    # Update existing counter's user
                    counter.user = user
                db.session.commit()
                flash(f'Counter "{counter_name}" assigned to user "{username}".', 'success')

        return redirect(url_for('manage_counters'))

    counters = Counter.query.all()
    return render_template('manage_counters.html', counters=counters)

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

@app.route('/admin/users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        is_admin = bool(request.form.get('is_admin'))

        if username and password:
            existing = User.query.filter_by(username=username).first()
            if existing:
                return "User already exists", 400
            user = User(username=username, is_admin=is_admin)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('manage_users'))
        else:
            return "Username and password required", 400

    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    # Prevent deleting self or last admin if needed
    if user.id == session.get('user_id'):
        return "Cannot delete yourself", 400
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('manage_users'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)
    return redirect(url_for('login'))

def sync_initial_items_to_counters():
    # Get latest initial prepared session
    initial_session = InitialPreparedSession.query.order_by(InitialPreparedSession.created_at.desc()).first()
    if not initial_session:
        return

    counters = Counter.query.all()

    for counter in counters:
        for ip_item in initial_session.items:
            # Check if CounterItemStock entry exists for this item, session and counter
            existing = CounterItemStock.query.filter_by(
                counter_id=counter.id,
                session_id=initial_session.id,
                item_name=ip_item.name
            ).first()

            if not existing:
                new_stock = CounterItemStock(
                    item_name=ip_item.name,
                    counter_id=counter.id,
                    session_id=initial_session.id,
                    available_stock=0  # initialize to zero
                )
                db.session.add(new_stock)

    db.session.commit()

@app.route('/admin/init_db', methods=['POST'])
@admin_required
def init_db():
    try:
        # Drop all tables
        db.drop_all()
        # Create all tables
        db.create_all()
        return "Database tables deleted and recreated successfully.", 200
    except Exception as e:
        return f"Error initializing database: {str(e)}", 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Create default admin if none exists
        admin_user = User.query.filter_by(is_admin=True).first()
        if not admin_user:
            admin_password = 'adminpass'  # Change to secure password or load from env
            admin = User(username='admin', is_admin=True)
            admin.set_password(admin_password)
            db.session.add(admin)
            db.session.commit()
            print('Default admin user created with username: admin and password: adminpass')

        # Sync initial items to counters (if you want automatic syncing on startup)
        sync_initial_items_to_counters()

    app.run(debug=True)


    app.run(debug=True)
