from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_cors import CORS
from config import Config
from models import db, Product, User, Sale, AuditLog, Setting, Category, Supplier, SupplierOrder, ProductHistory, Customer
from sqlalchemy import func, desc
import os
from werkzeug.utils import secure_filename
import csv
import io
import json
from flask import send_file, make_response
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from flask import send_file
from collections import defaultdict
from datetime import datetime, timedelta
import requests
from requests.auth import HTTPBasicAuth
import base64
from flask_wtf import FlaskForm
from wtforms import HiddenField
import uuid

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = 'replace-this-with-a-secure-key'
db.init_app(app)
CORS(app)

with app.app_context():
    db.create_all()

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = os.path.join('static', 'uploads', 'logos')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(role=None):
    def decorator(f):
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if role and session.get('role') != role:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def home():
    return render_template('landing.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'staff')
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('signup'))
        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            log_audit('User Login', f'User {username} logged in.')
            flash('Logged in successfully!', 'success')
            return redirect(url_for('products_page'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/products', methods=['GET', 'POST'])
@login_required()
def products_page():
    can_edit = session.get('role') == 'admin'
    search = request.args.get('search', '')
    category_id = request.args.get('category', type=int)
    supplier_id = request.args.get('supplier', type=int)
    stock_status = request.args.get('stock_status', '')
    sort = request.args.get('sort', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10

    query = Product.query
    if search:
        query = query.filter(
            (Product.name.ilike(f'%{search}%')) |
            (Product.barcode.ilike(f'%{search}%')) |
            (Product.description.ilike(f'%{search}%'))
        )
    if category_id:
        query = query.filter(Product.category_id == category_id)
    if supplier_id:
        query = query.filter(Product.supplier_id == supplier_id)
    if stock_status == 'low':
        query = query.filter(Product.stock < 5)
    elif stock_status == 'out':
        query = query.filter(Product.stock == 0)
    if sort == 'name':
        query = query.order_by(Product.name)
    elif sort == 'price':
        query = query.order_by(Product.selling_price)
    elif sort == 'stock':
        query = query.order_by(Product.stock)

    products = query.paginate(page=page, per_page=per_page)
    categories = Category.query.all()
    suppliers = Supplier.query.all()
    units = ['KGs', 'Grams', 'Liters', 'Milliliters', 'Pieces', 'Bales', 'Packs', 'Boxes', 'Cartons', 'Dozens', 'Meters', 'Rolls', 'Bottles', 'Bags', 'Trays']

    return render_template('products.html',
        products=products,
        categories=categories,
        suppliers=suppliers,
        units=units,
        can_edit=can_edit,
        search=search,
        category_id=category_id,
        supplier_id=supplier_id,
        stock_status=stock_status,
        sort=sort,
        threshold=5  # For low stock badge
    )

@app.route('/products/edit/<int:product_id>', methods=['GET', 'POST'])
@login_required(role='admin')
def edit_product_page(product_id):
    units = ['KGs', 'Grams', 'Liters', 'Milliliters', 'Pieces', 'Bales', 'Packs', 'Boxes', 'Cartons', 'Dozens', 'Meters', 'Rolls', 'Bottles', 'Bags', 'Trays']
    product = Product.query.get_or_404(product_id)
    categories = Category.query.all()
    suppliers = Supplier.query.all()
    if request.method == 'POST':
        old_data = f"name={product.name}, price={product.selling_price}, stock={product.stock}, unit={product.unit}"
        product.name = request.form['name']
        product.selling_price = float(request.form['selling_price'])
        product.stock = int(request.form['stock'])
        product.unit = request.form['unit']
        # Update category and supplier
        category_id = request.form.get('category')
        supplier_id = request.form.get('supplier')
        product.category_id = int(category_id) if category_id else None
        product.supplier_id = int(supplier_id) if supplier_id else None
        db.session.commit()
        log_audit('Edit Product', f'Product {product.name} edited by {session.get("username")}. Old: {old_data}')
        return redirect(url_for('products_page'))
    return render_template('edit_product.html', product=product, units=units, categories=categories, suppliers=suppliers)

@app.route('/products/delete/<int:product_id>')
@login_required(role='admin')
def delete_product_page(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    log_audit('Delete Product', f'Product {product.name} deleted by {session.get("username")}')
    return redirect(url_for('products_page'))

@app.route('/products/import', methods=['POST'])
@login_required(role='admin')
def import_products():
    file = request.files['csv']
    if file:
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        reader = csv.DictReader(stream)
        for row in reader:
            product = Product(
                name=row['name'],
                selling_price=float(row['selling_price']),
                stock=int(row['stock']),
                unit=row['unit'],
                category_id=int(row['category_id']) if row['category_id'] else None,
                supplier_id=int(row['supplier_id']) if row['supplier_id'] else None,
                barcode=row.get('barcode'),
                image=row.get('image')
            )
            db.session.add(product)
        db.session.commit()
        flash('Products imported.', 'success')
    return redirect(url_for('products_page'))

@app.route('/products/export')
@login_required(role='admin')
def export_products():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['id', 'name', 'selling_price', 'stock', 'unit', 'category_id', 'supplier_id', 'barcode', 'image'])
    for p in Product.query.all():
        writer.writerow([p.id, p.name, p.selling_price, p.stock, p.unit, p.category_id, p.supplier_id, p.barcode, p.image])
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name='products.csv'
    )
@app.route('/sales/export')
@login_required(role='admin')
def export_sales():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['id', 'product_id', 'product_name', 'quantity', 'total_price', 'payment_method', 'timestamp', 'customer_name', 'customer_contact'])
    for s in Sale.query.all():
        product = Product.query.get(s.product_id)
        writer.writerow([
            s.id, s.product_id, product.name if product else '', s.quantity, s.total_price,
            s.payment_method, s.timestamp, getattr(s, 'customer_name', ''), getattr(s, 'customer_contact', '')
        ])
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name='sales.csv'
    )

@app.route('/customers/export')
@login_required(role='admin')
def export_customers():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['id', 'name', 'business_name', 'contact_email', 'contact_phone', 'address', 'notes'])
    for c in Customer.query.all():
        writer.writerow([c.id, c.name, c.business_name, c.contact_email, c.contact_phone, c.address, c.notes])
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name='customers.csv'
    )

@app.route('/products/<int:product_id>/history')
@login_required()
def product_history(product_id):
    product = Product.query.get_or_404(product_id)
    history = ProductHistory.query.filter_by(product_id=product.id).order_by(ProductHistory.timestamp.desc()).all()
    return render_template('product_history.html', product=product, history=history)

class DummyForm(FlaskForm):
    pass

@app.route('/sales', methods=['GET', 'POST'])
@login_required()
def make_sale():
    form = DummyForm()
    payment_methods = ['Cash', 'Mpesa', 'Card', 'Other']
    receipt = None
    products = Product.query.all()

    if request.method == 'POST':
        product_ids = request.form.getlist('product_id[]')
        quantities = request.form.getlist('quantity[]')
        payment_method = request.form['payment_method']
        mpesa_phone = request.form.get('mpesa_phone', '').strip()
        items = []
        grand_total = 0
        transaction_id = uuid.uuid4().hex  # Generate a unique transaction ID
        sale_ids = []

        for pid, qty in zip(product_ids, quantities):
            product = Product.query.get(int(pid))
            qty = int(qty)
            if product and qty > 0 and product.stock >= qty:
                product.stock -= qty
                total = product.selling_price * qty
                sale = Sale(
                    product_id=product.id,
                    quantity=qty,
                    payment_method=payment_method,
                    total_price=total,
                    user_id=session.get('user_id'),
                    transaction_id=transaction_id,  # <-- Add this line
                )
                db.session.add(sale)
                db.session.commit()
                sale_ids.append(sale.id)
                items.append({
                    'product': product.name,
                    'quantity': qty,
                    'unit_price': product.selling_price,
                    'total': total
                })
                grand_total += total
            else:
                flash(f'Insufficient stock for {product.name}', 'danger')
                return redirect(request.url)

        # Mpesa STK Push
        if payment_method.lower() == 'mpesa':
            # Validate phone again on backend
            if not mpesa_phone or not mpesa_phone.startswith('07') or len(mpesa_phone) != 10:
                flash('Invalid Mpesa phone number.', 'danger')
                return redirect(request.url)
            # Format phone for Safaricom API (2547XXXXXXXX)
            saf_phone = '254' + mpesa_phone[1:]
            # Send STK Push for the grand total
            stk_response = mpesa_stk_push(
                phone_number=saf_phone,
                amount=grand_total,
                account_reference="DUKA",
                transaction_desc="Duka Sale Payment"
            )
            if stk_response.get('ResponseCode') == '0':
                flash('Mpesa payment request sent to customer\'s phone.', 'success')
            else:
                error_msg = stk_response.get('error') or stk_response.get('details') or 'Failed to initiate Mpesa payment. Please try again.'
                flash(f'Mpesa Error: {error_msg}', 'danger')

        receipt = {
            'payment_method': payment_method,
            'items': items,
            'grand_total': grand_total,
            'sale_id': sale_ids[0] if sale_ids else None,
            'transaction_id': transaction_id  # <-- Add this line
        }
        flash('Sale completed successfully!', 'success')
    return render_template('make_sale.html', form=form, products=products, payment_methods=payment_methods, receipt=receipt)

@app.route('/sales_list', methods=['GET'])
@login_required()
def sales_list():
    search = request.args.get('search', '')
    payment_method = request.args.get('payment_method', '')
    page = request.args.get('page', 1, type=int)
    query = Sale.query

    # If staff, only show their own sales
    if session.get('role') == 'staff':
        query = query.filter(Sale.user_id == session.get('user_id'))
    else:
        # Admins/managers see all sales
        if search:
            query = query.join(Product).filter(Product.name.ilike(f'%{search}%'))
        if payment_method:
            query = query.filter(Sale.payment_method == payment_method)

    sales = query.order_by(Sale.timestamp.desc()).paginate(page=page, per_page=20)
    total_sales = sum(sale.total_price for sale in sales.items)
    can_delete = session.get('role') == 'admin'
    payment_methods = ['Cash', 'Mpesa', 'Card', 'Other']

    return render_template(
        'sales_list.html',
        sales=sales,
        total_sales=total_sales,
        can_delete=can_delete,
        payment_methods=payment_methods,
        search=search,
        payment_method=payment_method
    )

@app.route('/delete_sale/<int:sale_id>', methods=['POST'])
def delete_sale(sale_id):
    if session.get('role') != 'admin':
        flash('Only admins can delete sales.', 'danger')
        return redirect(url_for('sales_list'))
    sale = Sale.query.get_or_404(sale_id)
    db.session.delete(sale)
    db.session.commit()
    log_audit('Delete Sale', f'Sale ID {sale_id} deleted by {session.get("username")}')
    flash('Sale deleted.', 'success')
    return redirect(url_for('sales_list'))

@app.route('/admin/users')
@login_required(role='admin')
def user_list():
    users = User.query.all()
    return render_template('user_list.html', users=users)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required(role='admin')
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        if user.id == session['user_id']:
            flash("You can't change your own role.", 'danger')
            return redirect(url_for('user_list'))
        user.role = request.form['role']
        db.session.commit()
        log_audit('Edit User', f'User {user.username} role changed from {old_role} to {user.role} by {session.get("username")}')
        flash('User role updated.', 'success')
        return redirect(url_for('user_list'))
    return render_template('edit_user.html', user=user)

@app.route('/admin/users/delete/<int:user_id>')
@login_required(role='admin')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == session['user_id']:
        flash("You can't delete your own account.", 'danger')
        return redirect(url_for('user_list'))
    db.session.delete(user)
    db.session.commit()
    log_audit('Delete User', f'User {user.username} deleted by {session.get("username")}')
    flash('User deleted.', 'success')
    return redirect(url_for('user_list'))

@app.route('/admin/audit-logs')
@login_required(role='admin')
def audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('audit_logs.html', logs=logs)

@app.route('/admin_dashboard')
@login_required()
def admin_dashboard():
    # KPIs
    total_sales = db.session.query(func.count(Sale.id)).scalar() or 0
    total_products = db.session.query(func.count(Product.id)).scalar() or 0
    total_customers = db.session.query(func.count(Customer.id)).scalar() or 0
    total_users = db.session.query(func.count(User.id)).scalar() or 0
    total_profit = db.session.query(
        func.sum(Sale.total_price - (Product.buying_price * Sale.quantity))
    ).join(Product).scalar() or 0

    # Low stock
    low_stock_products = Product.query.filter(Product.stock <= 5).all()
    low_stock_count = len(low_stock_products)

    # Recent sales (last 5)
    recent_sales = (
        db.session.query(Sale, Product.name.label('product_name'))
        .join(Product)
        .order_by(Sale.timestamp.desc())
        .limit(5)
        .all()
    )
    recent_sales_data = []
    for sale, product_name in recent_sales:
        recent_sales_data.append({
            'date': sale.timestamp,
            'product_name': product_name,
            'total_price': sale.total_price,
            'customer_name': getattr(sale, 'customer_name', '-'),
            'payment_method': sale.payment_method
        })

    # Sales trend (last 7 days)
    today = datetime.today().date()
    sales_trend = []
    labels = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        total = db.session.query(func.sum(Sale.total_price)).filter(func.date(Sale.timestamp) == day).scalar() or 0
        sales_trend.append(float(total))
        labels.append(day.strftime('%a'))
    sales_trend_data = {'labels': labels, 'values': sales_trend}

    return render_template(
        'admin_dashboard.html',
        total_sales=total_sales,
        total_products=total_products,
        total_customers=total_customers,
        total_users=total_users,
        total_profit=total_profit,
        low_stock_count=low_stock_count,
        low_stock_products=low_stock_products,
        recent_sales=recent_sales_data,
        sales_trend_data=sales_trend_data
    )

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required(role='admin')
def system_settings():
    # Business details keys
    business_keys = [
        'business_name', 'business_address', 'business_email', 'business_phone',
        'paybill_number_1', 'paybill_number_2', 'paybill_number_3', 'paybill_number_4',
        'payment_method_1', 'payment_method_2', 'payment_method_3', 'payment_method_4',
        'bank_name', 'bank_account_name', 'bank_account_number', 'tax_id', 'currency_symbol',
        'receipt_footer', 'date_format', 'session_timeout', 'password_policy', 'signup_enabled'
    ]
    # Get or create settings
    settings = {key: (Setting.query.filter_by(key=key).first() or Setting(key=key, value='')) for key in business_keys}
    for s in settings.values():
        if not s.id:
            db.session.add(s)
    db.session.commit()

    # Inventory and sales settings
    threshold_setting = Setting.query.filter_by(key='low_stock_threshold').first()
    if not threshold_setting:
        threshold_setting = Setting(key='low_stock_threshold', value='5')
        db.session.add(threshold_setting)
        db.session.commit()
    payment_methods_setting = Setting.query.filter_by(key='payment_methods').first()
    if not payment_methods_setting:
        payment_methods_setting = Setting(key='payment_methods', value='Cash,Mpesa,Other')
        db.session.add(payment_methods_setting)
        db.session.commit()

    # Logo setting
    logo_setting = Setting.query.filter_by(key='business_logo').first()
    if not logo_setting:
        logo_setting = Setting(key='business_logo', value='')
        db.session.add(logo_setting)
        db.session.commit()

    if request.method == 'POST':
        # Business details
        for key in business_keys:
            if key in request.form:
                settings[key].value = request.form[key]
        # Inventory
        if 'threshold' in request.form:
            threshold_setting.value = request.form['threshold']
        # Payment methods
        if 'payment_methods' in request.form:
            payment_methods_setting.value = request.form['payment_methods']
        # Logo upload
        if 'business_logo' in request.files:
            file = request.files['business_logo']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file.save(filepath)
                logo_setting.value = filepath
        db.session.commit()
        flash('Settings updated.', 'success')
        return redirect(url_for('system_settings'))

    categories = Category.query.all()
    return render_template(
        'system_settings.html',
        settings=settings,
        threshold=threshold_setting.value,
        payment_methods=payment_methods_setting.value,
        categories=categories,
        logo=logo_setting.value
    )

@app.route('/admin/settings/overview')
@login_required(role='admin')
def system_settings_overview():
    return render_template('system_settings_overview.html')

@app.route('/admin/settings/business', methods=['GET', 'POST'])
@login_required(role='admin')
def edit_business_details():
    keys = ['business_name', 'business_address', 'business_contact', 'tax_info', 'business_email', 'website', 'receipt_footer', 'business_logo']
    settings = {key: Setting.query.filter_by(key=key).first() for key in keys}

    if request.method == 'POST':
        # Handle logo upload
        logo_file = request.files.get('business_logo')
        if logo_file and allowed_file(logo_file.filename):
            filename = secure_filename(logo_file.filename)
            logo_path = os.path.join(UPLOAD_FOLDER, filename)
            logo_file.save(logo_path)
            # Save relative path to DB
            logo_setting = settings.get('business_logo')
            rel_path = os.path.join('uploads', 'logos', filename)
            if logo_setting:
                logo_setting.value = rel_path
            else:
                logo_setting = Setting(key='business_logo', value=rel_path)
                db.session.add(logo_setting)

        # Handle other fields
        for key in keys:
            if key == 'business_logo':
                continue
            value = request.form.get(key)
            if value is not None:
                setting = settings.get(key)
                if setting:
                    setting.value = value
                else:
                    setting = Setting(key=key, value=value)
                    db.session.add(setting)
        db.session.commit()
        flash('Business details updated!', 'success')
        return redirect(url_for('system_settings'))
    return render_template('edit_business_details.html', settings=settings)

@app.route('/admin/settings/inventory', methods=['GET', 'POST'])
@login_required(role='admin')
def edit_inventory_settings():
    threshold_setting = Setting.query.filter_by(key='low_stock_threshold').first()
    currency_setting = Setting.query.filter_by(key='currency_symbol').first()
    categories = Category.query.all()
    if not threshold_setting:
        threshold_setting = Setting(key='low_stock_threshold', value='5')
        db.session.add(threshold_setting)
    if not currency_setting:
        currency_setting = Setting(key='currency_symbol', value='KES')
        db.session.add(currency_setting)
    db.session.commit()

    if request.method == 'POST':
        if 'threshold' in request.form:
            threshold_setting.value = request.form['threshold']
        if 'currency_symbol' in request.form:
            currency_setting.value = request.form['currency_symbol']
        if 'add_category' in request.form and request.form['add_category'].strip():
            cat = request.form['add_category'].strip()
            if not Category.query.filter_by(name=cat).first():
                db.session.add(Category(name=cat))
        if 'delete_category' in request.form:
            cat_id = int(request.form['delete_category'])
            cat = Category.query.get(cat_id)
            if cat:
                db.session.delete(cat)
        db.session.commit()
        flash('Inventory settings updated.', 'success')
        return redirect(url_for('edit_inventory_settings'))

    settings = {
        'currency_symbol': currency_setting,
    }
    return render_template(
        'edit_inventory_settings.html',
        threshold=threshold_setting.value,
        settings=settings,
        categories=Category.query.all()
    )

@app.route('/admin/settings/sales', methods=['GET', 'POST'])
@login_required(role='admin')
def edit_sales_settings():
    payment_methods_setting = Setting.query.filter_by(key='payment_methods').first()
    receipt_footer_setting = Setting.query.filter_by(key='receipt_footer').first()
    if not payment_methods_setting:
        payment_methods_setting = Setting(key='payment_methods', value='Cash,Mpesa,Other')
        db.session.add(payment_methods_setting)
    if not receipt_footer_setting:
        receipt_footer_setting = Setting(key='receipt_footer', value='')
        db.session.add(receipt_footer_setting)
    db.session.commit()

    if request.method == 'POST':
        if 'payment_methods' in request.form:
            payment_methods_setting.value = request.form['payment_methods']
        if 'receipt_footer' in request.form:
            receipt_footer_setting.value = request.form['receipt_footer']
        db.session.commit()
        flash('Sales settings updated.', 'success')
        return redirect(url_for('edit_sales_settings'))

    settings = {
        'receipt_footer': receipt_footer_setting,
    }
    return render_template(
        'edit_sales_settings.html',
        payment_methods=payment_methods_setting.value,
        settings=settings
    )

@app.route('/admin/settings/user-security', methods=['GET', 'POST'])
@login_required(role='admin')
def edit_user_security_settings():
    password_policy_setting = Setting.query.filter_by(key='password_policy').first()
    signup_enabled_setting = Setting.query.filter_by(key='signup_enabled').first()
    session_timeout_setting = Setting.query.filter_by(key='session_timeout').first()
    if not password_policy_setting:
        password_policy_setting = Setting(key='password_policy', value='8')
        db.session.add(password_policy_setting)
    if not signup_enabled_setting:
        signup_enabled_setting = Setting(key='signup_enabled', value='yes')
        db.session.add(signup_enabled_setting)
    if not session_timeout_setting:
        session_timeout_setting = Setting(key='session_timeout', value='30')
        db.session.add(session_timeout_setting)
    db.session.commit()

    if request.method == 'POST':
        if 'password_policy' in request.form:
            password_policy_setting.value = request.form['password_policy']
        if 'signup_enabled' in request.form:
            signup_enabled_setting.value = request.form['signup_enabled']
        if 'session_timeout' in request.form:
            session_timeout_setting.value = request.form['session_timeout']
        db.session.commit()
        flash('User & security settings updated.', 'success')
        return redirect(url_for('edit_user_security_settings'))

    settings = {
        'password_policy': password_policy_setting,
        'signup_enabled': signup_enabled_setting,
        'session_timeout': session_timeout_setting,
    }
    return render_template(
        'edit_user_security_settings.html',
        settings=settings
    )

@app.route('/admin/settings/other', methods=['GET', 'POST'])
@login_required(role='admin')
def edit_other_settings():
    date_format_setting = Setting.query.filter_by(key='date_format').first()
    if not date_format_setting:
        date_format_setting = Setting(key='date_format', value='%Y-%m-%d %H:%M:%S')
        db.session.add(date_format_setting)
    db.session.commit()

    if request.method == 'POST':
        if 'date_format' in request.form:
            date_format_setting.value = request.form['date_format']
        db.session.commit()
        flash('Other settings updated.', 'success')
        return redirect(url_for('edit_other_settings'))

    settings = {
        'date_format': date_format_setting,
    }
    return render_template(
        'edit_other_settings.html',
        settings=settings
    )

@app.route('/admin/export')
@login_required(role='admin')
def export_data():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Name', 'Price', 'Stock', 'Unit'])
    for product in Product.query.all():
        writer.writerow([product.id, product.name, product.selling_price, product.stock, product.unit])
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name='products_export.csv'
    )

@app.route('/admin/backup')
@login_required(role='admin')
def backup_data():
    data = {
        'products': [dict(id=p.id, name=p.name, price=p.price, stock=p.stock, unit=p.unit) for p in Product.query.all()],
        'users': [dict(id=u.id, username=u.username, role=u.role) for u in User.query.all()],
        'sales': [dict(id=s.id, product_id=s.product_id, quantity=s.quantity, total_price=s.total_price, payment_method=s.payment_method, timestamp=str(s.timestamp)) for s in Sale.query.all()],
        'categories': [dict(id=c.id, name=c.name) for c in Category.query.all()],
        'settings': [dict(key=s.key, value=s.value) for s in Setting.query.all()]
    }
    output = io.BytesIO(json.dumps(data, indent=2).encode())
    return send_file(
        output,
        mimetype='application/json',
        as_attachment=True,
        download_name='duka_backup.json'
    )

@app.route('/admin/restore', methods=['POST'])
@login_required(role='admin')
def restore_data():
    file = request.files['json']
    if file:
        data = json.load(file)
        # You should clear existing data or merge as needed
        # Example for products:
        for p in data.get('products', []):
            product = Product.query.get(p['id']) or Product(id=p['id'])
            product.name = p['name']
            product.selling_price = p['price']
            product.stock = p['stock']
            product.unit = p['unit']
            db.session.add(product)
        db.session.commit()
        flash('Data restored (products only in this example).', 'success')
    return redirect(url_for('system_settings'))

@app.route('/suppliers')
@login_required(role='admin')
def suppliers_list():
    suppliers = Supplier.query.all()
    return render_template('suppliers_list.html', suppliers=suppliers)

@app.route('/suppliers/add', methods=['GET', 'POST'])
@login_required(role='admin')
def add_supplier():
    if request.method == 'POST':
        supplier = Supplier(
            name=request.form['name'],
            company=request.form.get('company'),
            contact_email=request.form.get('contact_email'),
            contact_phone=request.form.get('contact_phone'),
            address=request.form.get('address'),
            bank_name=request.form.get('bank_name'),
            bank_account=request.form.get('bank_account'),
            notes=request.form.get('notes')
        )
        db.session.add(supplier)
        db.session.commit()
        flash('Supplier added.', 'success')
        return redirect(url_for('suppliers_list'))
    return render_template('add_supplier.html')

@app.route('/suppliers/edit/<int:supplier_id>', methods=['GET', 'POST'])
@login_required(role='admin')
def edit_supplier(supplier_id):
    supplier = Supplier.query.get_or_404(supplier_id)
    if request.method == 'POST':
        supplier.name = request.form['name']
        supplier.company = request.form.get('company')
        supplier.contact_email = request.form.get('contact_email')
        supplier.contact_phone = request.form.get('contact_phone')
        supplier.address = request.form.get('address')
        supplier.bank_name = request.form.get('bank_name')
        supplier.bank_account = request.form.get('bank_account')
        supplier.notes = request.form.get('notes')
        db.session.commit()
        flash('Supplier updated.', 'success')
        return redirect(url_for('suppliers_list'))
    return render_template('edit_supplier.html', supplier=supplier)

@app.route('/suppliers/delete/<int:supplier_id>')
@login_required(role='admin')
def delete_supplier(supplier_id):
    supplier = Supplier.query.get_or_404(supplier_id)
    db.session.delete(supplier)
    db.session.commit()
    flash('Supplier deleted.', 'success')
    return redirect(url_for('suppliers_list'))

@app.route('/suppliers/<int:supplier_id>/products', methods=['GET', 'POST'])
@login_required(role='admin')
def supplier_products(supplier_id):
    supplier = Supplier.query.get_or_404(supplier_id)
    products = Product.query.all()
    if request.method == 'POST':
        product_id = int(request.form['product_id'])
        product = Product.query.get(product_id)
        if product:
            product.supplier_id = supplier.id
            db.session.commit()
            flash('Product linked to supplier.', 'success')
        return redirect(url_for('supplier_products', supplier_id=supplier.id))
    return render_template('supplier_products.html', supplier=supplier, products=products)

@app.route('/suppliers/<int:supplier_id>/orders', methods=['GET', 'POST'])
@login_required(role='admin')
def supplier_orders(supplier_id):
    supplier = Supplier.query.get_or_404(supplier_id)
    products = Product.query.filter_by(supplier_id=supplier.id).all()
    if request.method == 'POST':
        product_id = int(request.form['product_id'])
        quantity = int(request.form['quantity'])
        cost = float(request.form['cost'])
        order = SupplierOrder(
            supplier_id=supplier.id,
            product_id=product_id,
            quantity=quantity,
            cost=cost,
            status=request.form.get('status', 'Pending')
        )
        db.session.add(order)
        db.session.commit()
        flash('Order recorded.', 'success')
        return redirect(url_for('supplier_orders', supplier_id=supplier.id))
    orders = SupplierOrder.query.filter_by(supplier_id=supplier.id).all()
    return render_template('supplier_orders.html', supplier=supplier, products=products, orders=orders)

@app.route('/suppliers/<int:supplier_id>/report')
@login_required(role='admin')
def supplier_report(supplier_id):
    supplier = Supplier.query.get_or_404(supplier_id)
    orders = SupplierOrder.query.filter_by(supplier_id=supplier.id).all()
    total_purchases = sum(order.cost for order in orders)
    outstanding_orders = [order for order in orders if order.status != 'Delivered']
    return render_template('supplier_report.html', supplier=supplier, orders=orders, total_purchases=total_purchases, outstanding_orders=outstanding_orders)

@app.route('/suppliers/<int:supplier_id>/details')
@login_required(role='admin')
def supplier_details(supplier_id):
    supplier = Supplier.query.get_or_404(supplier_id)
    products = Product.query.filter_by(supplier_id=supplier.id).all()
    orders = SupplierOrder.query.filter_by(supplier_id=supplier.id).all()
    total_purchases = sum(order.cost for order in orders)
    outstanding_orders = [order for order in orders if order.status != 'Delivered']
    return render_template('supplier_report.html', supplier=supplier, products=products, orders=orders, total_purchases=total_purchases, outstanding_orders=outstanding_orders)
@app.route('/suppliers/import', methods=['POST'])
@login_required(role='admin')
def import_suppliers():
    file = request.files['csv']
    if file:
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        reader = csv.DictReader(stream)
        for row in reader:
            supplier = Supplier(
                name=row['name'],
                company=row.get('company'),
                contact_email=row.get('contact_email'),
                contact_phone=row.get('contact_phone'),
                address=row.get('address'),
                bank_name=row.get('bank_name'),
                bank_account=row.get('bank_account'),
                notes=row.get('notes')
            )
            db.session.add(supplier)
        db.session.commit()
        flash('Suppliers imported.', 'success')
    return redirect(url_for('suppliers_list'))

@app.route('/suppliers/export')
@login_required(role='admin')
def export_suppliers():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['id', 'name', 'company', 'contact_email', 'contact_phone', 'address', 'bank_name', 'bank_account', 'notes'])
    for s in Supplier.query.all():
        writer.writerow([s.id, s.name, s.company, s.contact_email, s.contact_phone, s.address, s.bank_name, s.bank_account, s.notes])
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name='suppliers.csv'
    )
@app.route('/products/add', methods=['GET', 'POST'])
@login_required(role='admin')
def add_product():
    categories = Category.query.all()
    suppliers = Supplier.query.all()
    units = ['KGs', 'Grams', 'Liters', 'Milliliters', 'Pieces', 'Bales', 'Packs', 'Boxes', 'Cartons', 'Dozens', 'Meters', 'Rolls', 'Bottles', 'Bags', 'Trays']
    if request.method == 'POST':
        name = request.form['name']
        buying_price = float(request.form['buying_price'])
        selling_price = float(request.form['selling_price'])
        stock = int(request.form['stock'])
        unit = request.form['unit']
        category_id = request.form.get('category')
        supplier_id = request.form.get('supplier')

        category_id = int(category_id) if category_id else None
        supplier_id = int(supplier_id) if supplier_id else None

        product = Product(
            name=request.form['name'],
            buying_price=float(request.form['buying_price']),
            selling_price=float(request.form['selling_price']),
            stock=int(request.form['stock']),
            unit=request.form['unit'],
            category_id=category_id,
            supplier_id=supplier_id,
            description=request.form.get('description')
        )
        db.session.add(product)
        db.session.commit()
        log_audit('Add Product', f'Product {product.name} added by user {session.get("username")}')
        flash('Product added.', 'success')
        return redirect(url_for('products_page'))
    return render_template('add_product.html', categories=categories, suppliers=suppliers, units=units)

@app.route('/products/bulk', methods=['POST'])
@login_required(role='admin')
def bulk_products():
    action = request.form['action']
    product_ids = request.form.getlist('product_ids')
    if action == 'delete':
        for pid in product_ids:
            product = Product.query.get(pid)
            db.session.delete(product)
    elif action == 'update_stock':
        new_stock = int(request.form['new_stock'])
        for pid in product_ids:
            product = Product.query.get(pid)
            product.stock = new_stock
    elif action == 'update_price':
        new_price = float(request.form['new_price'])
        for pid in product_ids:
            product = Product.query.get(pid)
            product.selling_price = new_price
    db.session.commit()
    flash('Bulk action completed.', 'success')
    return redirect(url_for('products_page'))

    # PDF receipt route
@app.route('/download_receipt/<int:sale_id>')
@login_required()
def download_receipt(sale_id):
    sale = Sale.query.get_or_404(sale_id)
    # Fetch all sales in the same transaction using transaction_id
    if sale.transaction_id:
        sales = Sale.query.filter_by(transaction_id=sale.transaction_id).all()
    else:
        sales = [sale]

    items = []
    grand_total = 0
    payment_method = sale.payment_method
    for s in sales:
        product = Product.query.get(s.product_id)
        items.append({
            'product': product.name if product else 'Unknown',
            'quantity': s.quantity,
            'unit_price': product.selling_price if product else s.total_price,
            'total': s.total_price
        })
        grand_total += s.total_price

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    y = height - 50
    # Business Details (replace with dynamic values if needed)
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, y, "Duka Yetu Gen Store")
    y -= 20
    p.setFont("Helvetica", 10)
    p.drawString(50, y, f"Location: Hill Tea")
    y -= 15
    p.drawString(50, y, f"Contact No: 0724375332")
    y -= 15
    p.drawString(50, y, f"Paybill: Equity Bank: 247247 Account No 0724375332")
    y -= 15
    p.drawString(50, y, f"KCB Bank: 522533 Account No: 5763631")
    y -= 25

    p.setFont("Helvetica-Bold", 12)
    p.drawString(50, y, f"Payment: {payment_method}")
    y -= 20

    # Table headers
    p.setFont("Helvetica-Bold", 10)
    p.drawString(50, y, "Product")
    p.drawString(200, y, "Qty")
    p.drawString(250, y, "Unit Price")
    p.drawString(350, y, "Total")
    y -= 15
    p.setFont("Helvetica", 10)
    p.line(50, y, 500, y)
    y -= 10

    # Loop through all items
    for item in items:
        p.drawString(50, y, str(item['product']))
        p.drawString(200, y, str(item['quantity']))
        p.drawString(250, y, str(item['unit_price']))
        p.drawString(350, y, str(item['total']))
        y -= 15
        if y < 80:  # Add new page if needed
            p.showPage()
            y = height - 50

    y -= 10
    p.line(50, y, 500, y)
    y -= 20
    p.setFont("Helvetica-Bold", 12)
    p.drawString(250, y, "Grand Total:")
    p.setFont("Helvetica-Bold", 12)
    p.drawString(350, y, str(grand_total))

    p.showPage()
    p.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="receipt.pdf", mimetype='application/pdf')

@app.route('/customers')
@login_required()
def customers_list():
    customers = Customer.query.all()
    return render_template('customers_list.html', customers=customers)

@app.route('/customers/add', methods=['GET', 'POST'])
@login_required()
def add_customer():
    if request.method == 'POST':
        customer = Customer(
            name=request.form['name'],
            business_name=request.form.get('business_name'),
            contact_email=request.form.get('contact_email'),
            contact_phone=request.form.get('contact_phone'),
            address=request.form.get('address'),
            notes=request.form.get('notes')
        )
        db.session.add(customer)
        db.session.commit()
        flash('Customer added.', 'success')
        return redirect(url_for('customers_list'))
    return render_template('add_customer.html')

@app.route('/customers/import', methods=['POST'])
@login_required(role='admin')
def import_customers():
    file = request.files['csv']
    if file:
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        reader = csv.DictReader(stream)
        for row in reader:
            customer = Customer(
                name=row['name'],
                business_name=row.get('business_name'),
                contact_email=row.get('contact_email'),
                contact_phone=row.get('contact_phone'),
                address=row.get('address'),
                notes=row.get('notes')
            )
            db.session.add(customer)
        db.session.commit()
        flash('Customers imported.', 'success')
    return redirect(url_for('customers_list'))

@app.route('/customers/<int:customer_id>/sale', methods=['GET', 'POST'])
@login_required()
def make_customer_sale(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    products = Product.query.all()
    payment_methods = ['Cash', 'Mpesa', 'Other']
    receipt = None

    if request.method == 'POST':
        product_ids = request.form.getlist('product_id[]')
        quantities = request.form.getlist('quantity[]')
        payment_method = request.form['payment_method']
        mpesa_phone = request.form.get('mpesa_phone', '').strip()
        items = []
        grand_total = 0
        transaction_id = uuid.uuid4().hex  # Generate a unique transaction ID
        sale_ids = []

        for pid, qty in zip(product_ids, quantities):
            product = Product.query.get(int(pid))
            qty = int(qty)
            if product and qty > 0 and product.stock >= qty:
                product.stock -= qty
                total = product.selling_price * qty
                sale = Sale(
                    product_id=product.id,
                    quantity=qty,
                    payment_method=payment_method,
                    total_price=total,
                    customer_name=customer.name,
                    customer_contact=customer.contact_phone
                )
                db.session.add(sale)
                db.session.commit()
                sale_ids.append(sale.id)
                items.append({
                    'product': product.name,
                    'quantity': qty,
                    'unit_price': product.selling_price,
                    'total': total
                })
                grand_total += total
            else:
                flash(f'Insufficient stock for {product.name}', 'danger')
                return redirect(request.url)

        # Mpesa STK Push logic (same as make_sale)
        if payment_method.lower() == 'mpesa':
            if not mpesa_phone or not mpesa_phone.startswith('07') or len(mpesa_phone) != 10:
                flash('Invalid Mpesa phone number.', 'danger')
                return redirect(request.url)
            saf_phone = '254' + mpesa_phone[1:]
            stk_response = mpesa_stk_push(
                phone_number=saf_phone,
                amount=grand_total,
                account_reference="DUKA",
                transaction_desc=f"Sale for {customer.name}"
            )
            if stk_response.get('ResponseCode') == '0':
                flash('Mpesa payment request sent to customer\'s phone.', 'success')
            else:
                error_msg = stk_response.get('error') or stk_response.get('details') or 'Failed to initiate Mpesa payment. Please try again.'
                flash(f'Mpesa Error: {error_msg}', 'danger')

        receipt = {
            'customer': customer.name,
            'contact': customer.contact_phone,
            'payment_method': payment_method,
            'items': items,
            'grand_total': grand_total,
            'sale_id': sale_ids[0] if sale_ids else None
        }
        flash('Sale completed successfully!', 'success')
    return render_template('customer_sale.html', customer=customer, products=products, payment_methods=payment_methods, receipt=receipt)

@app.route('/customers/<int:customer_id>/edit', methods=['GET', 'POST'])
def edit_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    if request.method == 'POST':
        customer.name = request.form['name']
        customer.business_name = request.form.get('business_name')
        customer.contact_email = request.form.get('contact_email')
        customer.contact_phone = request.form.get('contact_phone')
        customer.address = request.form.get('address')
        customer.notes = request.form.get('notes')
        db.session.commit()
        flash('Customer updated.', 'success')
        return redirect(url_for('customers_list'))
    return render_template('add_customer.html', customer=customer, edit=True)

@app.route('/customers/<int:customer_id>/delete')
def delete_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    db.session.delete(customer)
    db.session.commit()
    flash('Customer deleted.', 'success')
    return redirect(url_for('customers_list'))

@app.route('/restock_product/<int:product_id>', methods=['GET', 'POST'])
def restock_product(product_id):
    # Only allow admin
    if session.get('role') != 'admin':
        flash('Only admins can restock products.', 'danger')
        return redirect(url_for('products_page'))

    product = Product.query.get_or_404(product_id)
    if request.method == 'POST':
        try:
            add_stock = int(request.form['add_stock'])
            if add_stock > 0:
                product.stock += add_stock
                db.session.commit()
                flash(f'{product.name} restocked by {add_stock}.', 'success')
            else:
                flash('Enter a positive number.', 'warning')
        except Exception:
            flash('Invalid input.', 'danger')
        return redirect(url_for('products_page'))

    return render_template('restock_product.html', product=product)

@app.route('/sales_breakdown', methods=['GET'])
@login_required()
def sales_breakdown():
    if session.get('role') == 'staff':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))
    # Get all sales, newest first
    sales = Sale.query.order_by(Sale.timestamp.desc()).all()
    breakdown = defaultdict(list)
    daily_totals = defaultdict(lambda: {'total': 0, 'profit': 0})
    for sale in sales:
        day = sale.timestamp.strftime('%Y-%m-%d')
        product = Product.query.get(sale.product_id)
        profit = (product.selling_price - product.buying_price) * sale.quantity if product else 0
        breakdown[day].append({
            'time': sale.timestamp.strftime('%H:%M'),
            'product': product.name if product else '',
            'quantity': sale.quantity,
            'unit_price': product.selling_price if product else '',
            'buying_price': product.buying_price if product else '',
            'total_price': sale.total_price,
            'profit': profit,
            'payment_method': sale.payment_method,
            'user': sale.user.username if sale.user else ''
        })
        daily_totals[day]['total'] += sale.total_price
        daily_totals[day]['profit'] += profit

    # Sort days descending
    sorted_days = sorted(breakdown.keys(), reverse=True)

    return render_template(
        'sales_breakdown.html',
        breakdown=breakdown,
        daily_totals=daily_totals,
        sorted_days=sorted_days
    )

@app.route('/mpesa_callback', methods=['POST'])
def mpesa_callback():
    data = request.get_json()
    print("Mpesa Callback received:", data)
    # TODO: Parse data and update sale/payment status in your DB
    # Example: Check ResultCode, update Sale record, log audit, etc.
    return {"ResultCode": 0, "ResultDesc": "Accepted"}

def get_business_info():
    keys = [
        'business_name', 'business_address', 'business_phone', 'business_email',
        'paybill_number_1', 'paybill_number_2', 'paybill_number_3', 'paybill_number_4',
        'payment_method_1', 'payment_method_2', 'payment_method_3', 'payment_method_4'
    ]
    info = {}
    for key in keys:
        setting = Setting.query.filter_by(key=key).first()
        info[key] = setting.value if setting else ''
    return info

def mpesa_stk_push(phone_number, amount, account_reference, transaction_desc):
    consumer_key = os.environ.get('MPESA_CONSUMER_KEY')
    consumer_secret = os.environ.get('MPESA_CONSUMER_SECRET')
    shortcode = os.environ.get('MPESA_SHORTCODE')
    passkey = os.environ.get('MPESA_PASSKEY')

    if not all([consumer_key, consumer_secret, shortcode, passkey]):
        print("Mpesa credentials are not set in environment variables.")
        return {"error": "Mpesa credentials missing. Please contact admin."}

    # Get access token
    token_url = 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
    r = requests.get(token_url, auth=HTTPBasicAuth(consumer_key, consumer_secret))
    if r.status_code != 200:
        print("Failed to get access token:", r.text)
        return {"error": "Failed to get access token", "details": r.text}
    try:
        access_token = r.json()['access_token']
    except Exception as e:
        print("Error decoding access token response:", r.text)
        return {"error": "Invalid access token response", "details": r.text}

    # Prepare password
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    data_to_encode = shortcode + passkey + timestamp
    password = base64.b64encode(data_to_encode.encode()).decode()

    # STK Push request
    stk_url = 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
    headers = {'Authorization': f'Bearer {access_token}'}
    payload = {
        "BusinessShortCode": shortcode,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": int(amount),
        "PartyA": phone_number,
        "PartyB": shortcode,
        "PhoneNumber": phone_number,
        "CallBackURL": "https://bardic-rhea-overstowed.ngrok-free.dev",
        "AccountReference": account_reference,
        "TransactionDesc": transaction_desc
    }
    response = requests.post(stk_url, json=payload, headers=headers)
    if response.status_code != 200:
        print("STK Push failed:", response.text)
        return {"error": "STK Push failed", "details": response.text}
    try:
        return response.json()
    except Exception as e:
        print("Error decoding STK Push response:", response.text)
        return {"error": "Invalid STK Push response", "details": response.text}


def log_audit(action, details):
    user_id = session.get('user_id')
    log = AuditLog(user_id=user_id, action=action, details=details)
    db.session.add(log)
    db.session.commit()

# Set Mpesa credentials (for development only, remove in production)
import os

os.environ['MPESA_CONSUMER_KEY'] = 'BTVEcmGK7CGpPZQ0b9DjPmDaDFBhXgL9gIwfPPlVaC4eS0ic'
os.environ['MPESA_CONSUMER_SECRET'] = 'aCNgAk6EqWRJKCxaNtLI7hI49z1HPCMI2xS1dBd7WikfmsNsv3OSHGBaoLhXu98B'
os.environ['MPESA_SHORTCODE'] = '174379'
os.environ['MPESA_PASSKEY'] = 'bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919'

@app.context_processor
def inject_business_details():
    keys = ['business_name', 'business_address', 'business_contact', 'tax_info', 'business_email', 'website', 'receipt_footer', 'business_logo']
    settings = {key: Setting.query.filter_by(key=key).first() for key in keys}
    return dict(business_settings=settings)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)