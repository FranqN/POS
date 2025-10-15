from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, String

db = SQLAlchemy()

class ProductHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    change_type = db.Column(db.String(50))  # e.g. 'price', 'stock'
    old_value = db.Column(db.String(100))
    new_value = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User')

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    buying_price = db.Column(db.Float, nullable=False, default=0.0)
    selling_price = db.Column(db.Float, nullable=False, default=0.0)
    stock = db.Column(db.Integer, nullable=False)
    unit = db.Column(db.String(50))
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    category = db.relationship('Category', backref='products')
    supplier_id = db.Column(db.Integer, db.ForeignKey('supplier.id'))
    image = db.Column(db.String(200))
    barcode = db.Column(db.String(100))
    description = db.Column(db.Text)
    histories = db.relationship('ProductHistory', backref='product', lazy=True)

    def __repr__(self):
        return f'<Product {self.name}>'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='staff')  # 'admin' or 'staff'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Sale(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    payment_method = db.Column(db.String(20), nullable=False)
    customer_name = db.Column(db.String(100))
    customer_contact = db.Column(db.String(100))
    profit = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    product = db.relationship('Product')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User')
    transaction_id = db.Column(db.String(64), index=True)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(255), nullable=False)
    details = db.Column(db.Text)  # <-- Add this line
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    user = db.relationship('User')

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(255), nullable=False)

class Supplier(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128))
    company = db.Column(db.String(100))
    contact_email = db.Column(db.String(100))
    contact_phone = db.Column(db.String(50))
    address = db.Column(db.String(200))
    bank_name = db.Column(db.String(100))
    bank_account = db.Column(db.String(100))
    notes = db.Column(db.Text)
    products = db.relationship('Product', backref='supplier', lazy=True)
    # orders = db.relationship('SupplierOrder', backref='supplier', lazy=True)

class SupplierOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    supplier_id = db.Column(db.Integer, db.ForeignKey('supplier.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer)
    cost = db.Column(db.Float)
    status = db.Column(db.String(64))
    order_date = db.Column(db.DateTime)
    delivery_date = db.Column(db.DateTime)
    # Relationship to Supplier
    supplier = db.relationship('Supplier', backref='orders')
    # Relationship to Product
    product = db.relationship('Product')

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    business_name = db.Column(db.String(128))
    contact_email = db.Column(db.String(128))
    contact_phone = db.Column(db.String(64))
    address = db.Column(db.String(256))
    notes = db.Column(db.Text)
    # Add any other fields you need
