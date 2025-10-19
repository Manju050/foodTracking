import os
from flask import Flask, render_template, request, redirect, url_for, session, abort, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from io import StringIO
import csv
from datetime import datetime
from io import BytesIO
import re
import pytz
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = 'supersecretkey'

POSTGRES_LOCAL_URI = 'postgresql://lsandadi@localhost/prasadamtrackingdb'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or POSTGRES_LOCAL_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# Models
class InitialPreparedSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_name = db.Column(db.String(100), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=False)
    total_expected_devotees_count = db.Column(db.Integer, nullable=True)
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
    total_expected_to_prepare = db.Column(db.Integer, nullable=True)
    total_output_received = db.Column(db.Integer, nullable=True)

class CounterItemStock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(100), nullable=False)

    counter_id = db.Column(db.Integer, db.ForeignKey('counter.id', ondelete='CASCADE'), nullable=False)
    session_id = db.Column(db.Integer, db.ForeignKey('initial_prepared_session.id'), nullable=False)
    available_stock = db.Column(db.Float, default=0)  # save decimal values as well

    counter = db.relationship('Counter', backref=db.backref('counter_item_stocks', cascade='all, delete-orphan'))
    session = db.relationship('InitialPreparedSession', backref='counter_item_stocks')

    __table_args__ = (
        db.UniqueConstraint('item_name', 'counter_id', 'session_id', name='uq_item_counter_session'),
    )



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
    session_id = db.Column(db.Integer, db.ForeignKey('initial_prepared_session.id'), nullable=True)
    

class PreviousSavedSessions(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(1000), nullable=False)
    data = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # add this if missing
    session_id = db.Column(
        db.Integer, 
        db.ForeignKey('initial_prepared_session.id', ondelete='CASCADE'), 
        nullable=False
    )

class StockResetNotification(db.Model):
    """Track when normal counter stocks are reset to notify counter users"""
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('initial_prepared_session.id'), nullable=False)
    reset_timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    acknowledged_by_counters = db.Column(db.Text, default='')  # Comma-separated counter IDs who acknowledged
    
    def is_acknowledged_by_counter(self, counter_id):
        """Check if a counter has acknowledged this notification"""
        ack_ids = self.acknowledged_by_counters.split(',') if self.acknowledged_by_counters else []
        return str(counter_id) in ack_ids
    
    def acknowledge_by_counter(self, counter_id):
        """Mark notification as acknowledged by a counter"""
        ack_ids = self.acknowledged_by_counters.split(',') if self.acknowledged_by_counters else []
        if str(counter_id) not in ack_ids:
            ack_ids.append(str(counter_id))
            self.acknowledged_by_counters = ','.join(filter(None, ack_ids))

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

        # Update total_output_received for existing counter items matching session items
        for c_item in existing_counter_items:
            session_item = next((i for i in session.items if i.name == c_item.item_name), None)
            if session_item:
                pass
            else:
                # Remove item from counter if session item deleted
                db.session.delete(c_item)

    db.session.commit()

def create_default_counters():
    """
    Creates 15 default counters (Counter 1 to Counter 15) and 2 special counters.
    """
    created_count = 0
    
    # Create Counter 1 to Counter 15
    for i in range(1, 16):
        counter_name = f"Counter {i}"
        existing_counter = Counter.query.filter_by(name=counter_name).first()
        if not existing_counter:
            new_counter = Counter(name=counter_name, user_id=None)
            db.session.add(new_counter)
            created_count += 1
    
    # Create special counters
    special_counters = ['Main Stock', 'Varistha Vaishnava']
    for counter_name in special_counters:
        existing_counter = Counter.query.filter_by(name=counter_name).first()
        if not existing_counter:
            new_counter = Counter(name=counter_name, user_id=None)
            db.session.add(new_counter)
            created_count += 1
    
    if created_count > 0:
        db.session.commit()
        print(f"Created {created_count} new counters. Total counters now: {Counter.query.count()}")
    else:
        print(f"All default counters already exist. Total counters: {Counter.query.count()}")

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

@app.route('/admin/toggle_admin/<int:user_id>', methods=['POST'])
@admin_required
def toggle_admin_privilege(user_id):
    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()
    flash(f"Admin privilege {'granted' if user.is_admin else 'revoked'} for user {user.username}.", "success")
    return redirect(url_for('manage_users'))


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
                val = float(request.form[form_field])  # parse decimal values as well
                stock_entry.available_stock = val
            except ValueError:
                pass

    db.session.commit()
    flash('Stock updated successfully!', 'success')
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
        ).order_by(CounterItemStock.id).all()  # Display items in fixed order everytime
    
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

    # Check if the session is currently active
    if session_obj.is_active:  # assuming your model has an 'is_active' boolean field
        flash(f'Cannot delete active session "{session_obj.session_name}". Please deactivate it first.', 'warning')
        return redirect(url_for('initial_prepared'))

    # Delete all counter_item_stock entries associated with this session
    db.session.query(CounterItemStock).filter(
        CounterItemStock.session_id == session_obj.id
    ).delete(synchronize_session=False)

    # Delete the session itself
    db.session.delete(session_obj)
    db.session.commit()

    flash(f'Session "{session_obj.session_name}" and all related items were deleted.', 'success')
    return redirect(url_for('initial_prepared'))


@app.route('/admin/initial_prepared', methods=['GET', 'POST'])
@admin_required
def initial_prepared():
    if request.method == 'POST':
        session_name = request.form.get('session_name', '').strip()
        total_expected_devotees_count = request.form.get('total_expected_devotees_count', '').strip()
        item_names = request.form.getlist('item_name')
        toal_expecteds = request.form.getlist('total_expected_to_prepare')
        total_outputs = request.form.getlist('total_output_received')

        if not session_name:
            return "Session name is required", 400

        if InitialPreparedSession.query.filter_by(session_name=session_name).first():
            return "Session name already exists", 400

        # Get current UTC time (or modify your datetime source accordingly)
        utc_now = datetime.utcnow().replace(tzinfo=pytz.utc)

        # Define IST timezone
        ist = pytz.timezone('Asia/Kolkata')

        # Convert UTC time to IST
        ist_now = utc_now.astimezone(ist)

        # Format timestamp for filename (safe format without spaces/colons)
        timestamp_str = ist_now.strftime("%Y-%m-%d_%H:%M:%S")
        # Create session
        new_session = InitialPreparedSession(session_name=session_name,created_at=timestamp_str,total_expected_devotees_count=int(total_expected_devotees_count) if total_expected_devotees_count.isdigit() else None)
        db.session.add(new_session)
        db.session.flush()  # to get new_session.id

        # Add items
        for name, total_expcted ,total_otp in zip(item_names, toal_expecteds,total_outputs):
            if name.strip() and total_otp.isdigit() and total_expcted.isdigit():
                ip_item = InitialPreparedItem(
                    session_id=new_session.id,
                    name=name.strip(),
                    total_expected_to_prepare=int(total_expcted),
                    total_output_received=int(total_otp)
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
    if not total.isdigit():
        return redirect(url_for('admin_dashboard'))

    total_int = int(total)

    # Find the currently active session
    active_session = InitialPreparedSession.query.filter_by(is_active=True).first()
    if not active_session:
        # No session active — cannot update global stats
        flash("No active session found. Activate a session first.", "warning")
        return redirect(url_for('admin_dashboard'))

    # Get or create GlobalStats for this session only
    stats = GlobalStats.query.filter_by(session_id=active_session.id).first()
    if not stats:
        stats = GlobalStats(session_id=active_session.id, total_devotees_taken=total_int)
        db.session.add(stats)
    else:
        stats.total_devotees_taken = total_int

    db.session.commit()
    flash(f"Updated total devotees taken for session '{active_session.session_name}' to {total_int}.", "success")
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
        total_prepared_inputs = request.form.getlist('total_output_received')
        senior_taken_inputs = request.form.getlist('senior_taken')
        item_names = request.form.getlist('item_name_hidden')

        for idx, name in enumerate(item_names):
            ip_items = InitialPreparedItem.query.filter_by(name=name).all()
            T = int(total_prepared_inputs[idx]) if total_prepared_inputs[idx].isdigit() else 0
            S = int(senior_taken_inputs[idx]) if senior_taken_inputs[idx].isdigit() else 0
            for ip_item in ip_items:
                ip_item.total_output_received = T
                # You may extend InitialPreparedItem to store senior_taken if needed
            db.session.commit()
        return redirect(url_for('admin_dashboard'))

    active_session = InitialPreparedSession.query.filter_by(is_active=True).first()
    if active_session:
        session_items = InitialPreparedItem.query.filter_by(session_id=active_session.id).all()
    else:
        session_items = []

    from sqlalchemy import func

    stock_agg = []
    stock_map = {}

    if active_session:
        stats = GlobalStats.query.filter_by(session_id=active_session.id).first()
        total_devotees_taken = stats.total_devotees_taken if stats else 0
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

    else:
        total_devotees_taken = 0

    count = total_devotees_taken

    items_list = []

    for ip_item in session_items:
        name = ip_item.name
        T = ip_item.total_output_received
        S = 0  # senior_taken is zero by default; extend if tracked

        x = stock_map.get(name, 0)

        # Calculate consumed as total_output_received - available_stock - senior_taken
        consumed_calc = max(T - S - x, 0)

        denominator = T - S - x
        if denominator > 0 and count > 0:
            estimated_available = int(x * count / denominator)
        else:
            estimated_available = 0

        items_list.append({
            "name": name,
            "total_output_received": T,
            "senior_taken": S,
            "available_stock": x,
            "count": count,
            "estimated_available": estimated_available,
            "consumed": consumed_calc,    # Make sure this field is included
            "locked_total": True
        })


    sessions = InitialPreparedSession.query.order_by(InitialPreparedSession.created_at.desc()).all()

    return render_template('admin_dashboard.html',items=items_list, initial_session=active_session, sessions=sessions)


from sqlalchemy import func

@app.route('/admin/api_data')
@admin_required
def admin_api_data():
    # Get current active session
    session = InitialPreparedSession.query.filter_by(is_active=True).first()
    if not session:
        # No active session, return empty data
        return jsonify({"items": [], "total_devotees_taken": 0})
    
    session_id = session.id
    session_items = InitialPreparedItem.query.filter_by(session_id=session.id).all()
    total_expected_devotees_count = session.total_expected_devotees_count if session.total_expected_devotees_count else 0
    items_list = []
    for ip_item in session_items:
        # Calculate estimated devotee count who can take prasadam using formula: ((M+X)*D)/((T-S)-(M+X))
        # T - "Total output received" of the item
        # M - available stock in "Main Stock" counter
        # X - Sum of available stocks in all normal counters
        # S - available stock in "Varishta Vaishnava" counter
        # D - number of devotees taken prasadam in normal counters
        # Returns: estimated number of devotees that can be served with remaining stock
        item_name = ip_item.name
        # Get T: Total output received for this item
        item = InitialPreparedItem.query.filter_by(session_id=session_id, name=item_name).first()
        if not item:
            return 0
        T = item.total_output_received
        
        # Get M: Available stock in "Main Stock" counter
        main_stock = db.session.query(
            func.coalesce(func.sum(func.coalesce(CounterItemStock.available_stock, 0)), 0)
        ).join(
            Counter, Counter.id == CounterItemStock.counter_id
        ).filter(
            CounterItemStock.session_id == session_id,
            CounterItemStock.item_name == item_name,
            Counter.name == 'Main Stock'
        ).scalar()
        M = main_stock if main_stock else 0
        
        # Get X: Sum of available stocks in all normal counters (Counter 1-15)
        normal_stock = db.session.query(
            func.coalesce(func.sum(func.coalesce(CounterItemStock.available_stock, 0)), 0)
        ).join(
            Counter, Counter.id == CounterItemStock.counter_id
        ).filter(
            CounterItemStock.session_id == session_id,
            CounterItemStock.item_name == item_name,
            Counter.name.notin_(['Main Stock', 'Varistha Vaishnava'])
        ).scalar()
        X = normal_stock if normal_stock else 0
        
        # Get S: Available stock in "Varishta Vaishnava" counter
        varistha_stock = db.session.query(
            func.coalesce(func.sum(func.coalesce(CounterItemStock.available_stock, 0)), 0)
        ).join(
            Counter, Counter.id == CounterItemStock.counter_id
        ).filter(
            CounterItemStock.session_id == session_id,
            CounterItemStock.item_name == item_name,
            Counter.name == 'Varistha Vaishnava'
        ).scalar()
        S = varistha_stock if varistha_stock else 0
        
        # Get D: Number of devotees taken prasadam
        stats = GlobalStats.query.filter_by(session_id=session_id).first()
        D = stats.total_devotees_taken if stats else 0
        
        # Calculate formula: ((M+X)*D)/((T-S)-(M+X))
        numerator = (M + X) * D
        denominator = (T - S) - (M + X)
        total_consumed = max(denominator, 0)
        
        if denominator > 0 and numerator >= 0:
            estimated_count = numerator / denominator
            estimated_count = round(estimated_count, 2)
        else:
            estimated_count = 0

        status = 'OK'
        remaining_devotees_to_honour_prasadam = total_expected_devotees_count - D
        total_expected_devotees_count = session.total_expected_devotees_count if session.total_expected_devotees_count else 0
        if estimated_count >= remaining_devotees_to_honour_prasadam + 50 :
            status = 'success'
        elif estimated_count >= remaining_devotees_to_honour_prasadam or numerator == 0:
            status = 'ok'
        else :
            status = 'danger'
        
        items_list.append({
            "name": item_name,
            "total_output_received": T,
            "senior_taken": S,
            "available_stock": (M+X),
            "estimated_available": estimated_count,
            "consumed": total_consumed,
            "status": status

        })

    return jsonify({
        "items": items_list,
        "total_devotees_taken": D,
        "remaining_devotees_to_honour_prasadam": remaining_devotees_to_honour_prasadam,
        "total_expected_devotees_count":total_expected_devotees_count
    })


@app.route('/admin/reset_normal_counter_stocks', methods=['POST'])
@admin_required
def reset_normal_counter_stocks():
    """
    API to reset all available stock values to NULL for items in normal counters only.
    This excludes Main Stock and Varistha Vaishnava counters.
    Steps:
    1. Get the currently active session
    2. Find all normal counters (exclude 'Main Stock' and 'Varistha Vaishnava')
    3. Get all CounterItemStock entries for those normal counters in the active session
    4. Set their available_stock to NULL
    5. Commit changes and redirect with flash message
    """
    try:
        # Step 1: Get the currently active session
        active_session = InitialPreparedSession.query.filter_by(is_active=True).first()
        if not active_session:
            flash("No active session found. Please activate a session first.", "warning")
            return redirect(url_for('admin_dashboard'))
        
        # Step 2: Find all normal counter IDs (exclude Main Stock and Varistha Vaishnava)
        normal_counters = Counter.query.filter(
            Counter.name.notin_(['Main Stock', 'Varistha Vaishnava'])
        ).all()
        
        if not normal_counters:
            flash("No normal counters found in the system.", "warning")
            return redirect(url_for('admin_dashboard'))
        
        normal_counter_ids = [counter.id for counter in normal_counters]
        
        # Step 3 & 4: Get all CounterItemStock entries for normal counters and reset to NULL
        updated_count = db.session.query(CounterItemStock).filter(
            CounterItemStock.counter_id.in_(normal_counter_ids),
            CounterItemStock.session_id == active_session.id
        ).update(
            {CounterItemStock.available_stock: None},
            synchronize_session=False
        )
        
        # Step 5: Create notification for counter users
        notification = StockResetNotification(
            session_id=active_session.id,
            reset_timestamp=datetime.utcnow()
        )
        db.session.add(notification)
        
        # Step 6: Commit changes
        db.session.commit()
        
        flash(f"Successfully reset stock values for {updated_count} items across {len(normal_counters)} normal counters in session '{active_session.session_name}'. Counter users will be notified to refresh.", "success")
        return redirect(url_for('admin_dashboard'))
        
    except Exception as e:
        db.session.rollback()
        flash(f"Error resetting stocks: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))


@app.route('/counter/check_reset_notification/<int:counter_id>')
@login_required
def check_reset_notification(counter_id):
    """API endpoint for counter dashboards to check if stocks were reset"""
    user = db.session.get(User, session['user_id'])
    
    # Verify user has access to this counter
    counter = Counter.query.get_or_404(counter_id)
    if counter.user_id != user.id:
        return jsonify({"notification": False, "error": "Unauthorized"}), 403
    
    # Skip notification check for Main Stock and Varistha Vaishnava counters
    # since stock reset only affects normal counters
    if counter.name in ['Main Stock', 'Varistha Vaishnava']:
        return jsonify({"notification": False})
    
    active_session = InitialPreparedSession.query.filter_by(is_active=True).first()
    
    if not active_session:
        return jsonify({"notification": False})
    
    # Check for unacknowledged reset notifications for this specific counter
    notification = StockResetNotification.query.filter_by(
        session_id=active_session.id
    ).order_by(StockResetNotification.reset_timestamp.desc()).first()
    
    if notification and not notification.is_acknowledged_by_counter(counter_id):
        return jsonify({
            "notification": True,
            "message": "Stocks have been reset by admin. Please refresh the page to see updated values.",
            "notification_id": notification.id,
            "reset_time": notification.reset_timestamp.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify({"notification": False})


@app.route('/counter/acknowledge_reset/<int:notification_id>/<int:counter_id>', methods=['POST'])
@login_required
def acknowledge_reset(notification_id, counter_id):
    """Acknowledge that counter has refreshed and seen the reset notification"""
    user = db.session.get(User, session['user_id'])
    
    # Verify user has access to this counter
    counter = Counter.query.get_or_404(counter_id)
    if counter.user_id != user.id:
        return jsonify({"success": False, "error": "Unauthorized"}), 403
    
    notification = StockResetNotification.query.get_or_404(notification_id)
    
    notification.acknowledge_by_counter(counter_id)
    db.session.commit()
    
    return jsonify({"success": True})


@app.route('/admin/manage_items', methods=['GET', 'POST'])
@admin_required
def manage_items():
    if request.method == 'POST':
        name = request.form['item_name'].strip()
        total = request.form['total_output_received']
        if name and total.isdigit():
            # Add or update global item totals here
            items = Item.query.filter_by(name=name).all()
            if not items:
                # Create one item with counter_id null or zero to hold total info (optional design)
                # or create items for all counters as needed
                pass
            else:
                for item in items:
                    item.total_output_received = int(total)
            db.session.commit()
            return redirect(url_for('manage_items'))

    # Show all unique item names with totals
    items_all = Item.query.all()
    items_dict = {}
    for i in items_all:
        if i.name not in items_dict:
            items_dict[i.name] = i.total_output_received

    return render_template('manage_items.html', items=items_dict)

@app.route('/admin/save_snapshot', methods=['POST'])
@admin_required
def save_snapshot():
    # Get the currently active session
    active_session = InitialPreparedSession.query.filter_by(is_active=True).first()
    if not active_session:
        flash("No active session found. Please activate a session first.", "warning")
        return redirect(url_for('admin_dashboard'))

    # Aggregate total_output_received, available_stock grouped by item_name
    from sqlalchemy import func

    # Sum total_output_received from InitialPreparedItem to get session totals per item
    prepared_agg = db.session.query(
        InitialPreparedItem.name,
        func.coalesce(func.sum(InitialPreparedItem.total_output_received), 0)
    ).filter(
        InitialPreparedItem.session_id == active_session.id
    ).group_by(
        InitialPreparedItem.name
    ).all()
    prepared_map = {name: total for name, total in prepared_agg}

    # Sum available_stock from CounterItemStock per item for this session
    stock_agg = db.session.query(
        CounterItemStock.item_name,
        func.coalesce(func.sum(CounterItemStock.available_stock), 0)
    ).filter(
        CounterItemStock.session_id == active_session.id
    ).group_by(
        CounterItemStock.item_name
    ).all()
    stock_map = {name: total for name, total in stock_agg}

    # Fetch current session total devotees taken from GlobalStats
    stats = GlobalStats.query.filter_by(session_id=active_session.id).first()
    total_devotees_taken = stats.total_devotees_taken if stats else 0
    total_devotees_count = active_session.total_expected_devotees_count if active_session.total_expected_devotees_count else 0
    remaining_devotees_to_honour_prasadam = total_devotees_count - total_devotees_taken
    # Generate safe filename
    def sanitize_filename(s):
        return re.sub(r'[^a-zA-Z0-9-_]', '_', s)


    # Get current UTC time (or modify your datetime source accordingly)
    utc_now = datetime.utcnow().replace(tzinfo=pytz.utc)
    
    # Define IST timezone
    ist = pytz.timezone('Asia/Kolkata')
    
    # Convert UTC time to IST
    ist_now = utc_now.astimezone(ist)
    
    # Format timestamp for filename (safe format without spaces/colons)
    timestamp_str = ist_now.strftime("%Y-%m-%d_%H:%M:%S")
    
    # Use in filename
    safe_session_name = sanitize_filename(active_session.session_name or "session")
    filename = f"{safe_session_name}_honoured_prasadam_count_{total_devotees_taken}_{timestamp_str}.csv"


    output = StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Item Name', 'Total Prepared (T)', 'Senior Taken (S)', 'Available Stock (x)', 
        'Consumed (T - S - x)','Total Devotees count' ,'Total Devotees Taken Prasadam','Remaining devotees to honour prasadam' ,'Estimated Available for Serving'
    ])

    # Use all item names encountered in either prepared or stock data
    all_items = set(prepared_map.keys()).union(stock_map.keys())

    for name in all_items:
        T = prepared_map.get(name, 0)
        S = 0  # Adjust if you track senior_taken per session/item elsewhere
        x = stock_map.get(name, 0)

        consumed = max(T - S - x, 0)

        denominator = max(T - S - x, 1)
        est_available = int(x * total_devotees_taken / denominator) if denominator > 0 and total_devotees_taken > 0 else x

        writer.writerow([name, T, S, x, consumed,total_devotees_count,total_devotees_taken,remaining_devotees_to_honour_prasadam ,est_available])

    # Save feeding session snapshot in DB linked to current session
    snapshot = PreviousSavedSessions(data=output.getvalue(), session_id=active_session.id,filename=filename,timestamp=timestamp_str)
    db.session.add(snapshot)
    db.session.commit()

    flash(f"Snapshot saved for session '{active_session.session_name}'.", "success")
    return redirect(url_for('saved_sessions'))

@app.route('/admin/saved_sessions')
@admin_required
def saved_sessions():
    sessions = PreviousSavedSessions.query.order_by(PreviousSavedSessions.timestamp.desc()).all()
    return render_template('saved_sessions.html', sessions=sessions)


@app.route('/admin/saved_sessions/download/<int:session_id>')
@admin_required
def download_feeding_session(session_id):
    session_record = PreviousSavedSessions.query.get_or_404(session_id)
    csv_data = session_record.data
    csv_bytes = csv_data.encode('utf-8')

    # Use stored filename if available, else fallback to timestamp-based name
    filename = session_record.filename
    if not filename:
        filename = f'feeding_session_{session_record.timestamp.strftime("%Y%m%d_%H%M%S")}.csv'

    return send_file(
        BytesIO(csv_bytes),
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )

@app.route('/admin/saved_sessions/delete/<int:snapshot_id>', methods=['POST'])
@admin_required
def delete_feeding_session(snapshot_id):
    snapshot = PreviousSavedSessions.query.get_or_404(snapshot_id)
    db.session.delete(snapshot)
    db.session.commit()
    flash(f'Snapshot "{snapshot.filename}" deleted successfully.', 'success')
    return redirect(url_for('saved_sessions'))

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
        total_expected_to_prepares = request.form.getlist('total_expected_to_prepare')
        total_output_receiveds = request.form.getlist('total_output_received')
        total_expected_devotees_count = request.form.get('total_expected_devotees_count', '').strip()
        
        # Update total_expected_devotees_count on the session if valid
        if total_expected_devotees_count.isdigit():
            session.total_expected_devotees_count = int(total_expected_devotees_count)

        # Fetch existing items from DB
        existing_items = InitialPreparedItem.query.filter_by(session_id=session.id).all()
        existing_ids = {str(item.id) for item in existing_items}

        # Determine which items to delete (existing but not submitted)
        ids_to_delete = existing_ids - set(submitted_ids)
        for del_id in ids_to_delete:
            InitialPreparedItem.query.filter_by(id=int(del_id)).delete()

        for idx, item_id in enumerate(submitted_ids):
            name = item_names[idx].strip()

            total_otp = total_output_receiveds[idx].strip()
            total_exp_otp = total_expected_to_prepares[idx].strip()
            if not name or not total_otp.isdigit() or not total_exp_otp.isdigit():
                continue
            
            total_otp = int(total_otp)
            total_exp_otp = int(total_exp_otp)
        
            if item_id:  # existing item, update it
                if item_id in existing_ids:
                    item = InitialPreparedItem.query.get(int(item_id))
                    item.total_expected_to_prepare = total_exp_otp
                    item.name = name
                    item.total_output_received = total_otp
            else:
                # New item (empty or missing id)
                item = InitialPreparedItem(session_id=session.id, name=name,total_expected_to_prepare=total_exp_otp, total_output_received=total_otp)
                db.session.add(item)


        db.session.commit()
        sync_session_items_to_counters(session.id)
        return redirect(url_for('initial_prepared'))

    # GET: provide session items to template
    items = InitialPreparedItem.query.filter_by(session_id=session.id).all()
    return render_template('manage_session_items.html', session=session, items=items)



@app.route('/admin/session_items/<int:session_id>', methods=['GET'])
@admin_required
def session_items(session_id):
    session = InitialPreparedSession.query.get_or_404(session_id)  # Get session

    items = InitialPreparedItem.query.filter_by(session_id=session_id).all()

    items_data = [{
        'name': item.name,
        'total_expected_to_prepare': getattr(item, 'total_expected_to_prepare', None),
        'total_output_received': getattr(item, 'total_output_received', None)
    } for item in items]

    response = {
        'total_expected_devotees_count': session.total_expected_devotees_count,
        'items': items_data
    }

    return jsonify(response)


@app.route('/admin/sync_items')
@admin_required
def admin_sync_items():
    sync_initial_items_to_counters()
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/counter_items/<int:counter_id>', methods=['GET'])
@admin_required
def get_counter_items(counter_id):
    # Query current active session
    current_session = InitialPreparedSession.query.filter_by(is_active=True).first()
    if not current_session:
        return jsonify({'items': []})

    items = CounterItemStock.query.filter_by(counter_id=counter_id, session_id=current_session.id).add_columns(
        CounterItemStock.item_name,
        CounterItemStock.available_stock,
    ).all()

    items_list = [
        {
            'item_name': item_name,
            'available_stock': available_stock,
            'session_name': current_session.session_name
        }
        for _, item_name, available_stock in items
    ]

    return jsonify({'items': items_list})


@app.route('/admin/delete_counter/<int:counter_id>', methods=['POST'])
@admin_required
def delete_counter(counter_id):
    counter = Counter.query.get_or_404(counter_id)
    
    try:
        db.session.delete(counter)
        db.session.commit()
        flash(f'Counter "{counter.name}" deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting counter: {str(e)}', 'danger')
    
    return redirect(url_for('manage_counters'))

@app.route('/admin/manage_counters', methods=['GET', 'POST'])
@admin_required
def manage_counters():
    active_session = InitialPreparedSession.query.filter_by(is_active=True).first()
    current_session = InitialPreparedSession.query.filter_by(is_active=True).first()
    current_session_name = current_session.session_name if current_session else ""

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

    counters = Counter.query.order_by(Counter.id).all()  # Order by ID to prevent shuffling
    users = User.query.order_by(User.username).all()  # Sort users alphabetically
    return render_template('manage_counters.html', counters=counters, users=users, session_active=bool(active_session), current_session_name=current_session_name)

@app.route('/admin/update_multiple_counter_users', methods=['POST'])
@admin_required
def update_multiple_counter_users():
    counter_ids = request.form.getlist('counter_ids')
    user_ids = request.form.getlist('user_ids')
    
    if not counter_ids or not user_ids or len(counter_ids) != len(user_ids):
        flash('Invalid data provided.', 'danger')
        return redirect(url_for('manage_counters'))
    
    updated_counters = []
    
    # Update each counter
    for counter_id, user_id in zip(counter_ids, user_ids):
        counter = Counter.query.get(int(counter_id))
        user = User.query.get(int(user_id))
        
        if counter and user:
            counter.user = user
            updated_counters.append(f"{counter.name} → {user.username}")
    
    db.session.commit()
    
    # Create flash message
    if len(updated_counters) == 1:
        flash(f'Counter updated: {updated_counters[0]}', 'success')
    else:
        flash(f'{len(updated_counters)} counters updated successfully!', 'success')
    
    return redirect(url_for('manage_counters'))

@app.route('/admin/update_counter_user/<int:counter_id>', methods=['POST'])
@admin_required
def update_counter_user(counter_id):
    counter = Counter.query.get_or_404(counter_id)
    user_id = request.form.get('user_id')
    
    if not user_id:
        flash('User ID is required.', 'danger')
        return redirect(url_for('manage_counters'))
    
    user = User.query.get_or_404(int(user_id))
    counter.user = user
    db.session.commit()
    
    flash(f'Counter "{counter.name}" reassigned to user "{user.username}".', 'success')
    return redirect(url_for('manage_counters'))

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
                flash(f'User "{username}" already exists!', 'danger')
                return redirect(url_for('manage_users'))
            user = User(username=username, is_admin=is_admin)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash(f'User "{username}" created successfully!', 'success')
            return redirect(url_for('manage_users'))
        else:
            flash('Username and password are required!', 'danger')
            return redirect(url_for('manage_users'))

    users = User.query.order_by(User.username).all()  # Sort users alphabetically by username
    return render_template('manage_users.html', users=users)


@app.route('/admin/user_suggestions')
@admin_required
def user_suggestions():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])

    matched_users = User.query.filter(User.username.ilike(f'%{query}%')).limit(10).all()
    usernames = [user.username for user in matched_users]
    return jsonify(usernames)


@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    # Prevent deleting self or last admin if needed
    if user.id == session.get('user_id'):
        flash('Cannot delete yourself!', 'danger')
        return redirect(url_for('manage_users'))
    
    username = user.username  # Store username before deletion
    db.session.delete(user)
    db.session.commit()
    flash(f'User "{username}" deleted successfully!', 'success')
    return redirect(url_for('manage_users'))

@app.route('/logout', methods=['GET', 'POST'])
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

from sqlalchemy import text

@app.route('/admin/init_db', methods=['POST'])
@admin_required
def init_db():
    try:
        # Drop all tables with cascade
        db.session.execute(text('DROP SCHEMA public CASCADE;'))
        db.session.execute(text('CREATE SCHEMA public;'))
        db.session.commit()

        # Create all tables
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

        # Create default counters if they don't exist
        create_default_counters()

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

        # Create default counters if they don't exist
        create_default_counters()

        # Sync initial items to counters (if you want automatic syncing on startup)
        sync_initial_items_to_counters()

    app.run(debug=True)
