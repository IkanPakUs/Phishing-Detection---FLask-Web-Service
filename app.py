from flask import Flask
from flask_cors import CORS

def create_app():
    app = Flask(__name__)
    CORS(app, resources={"/api/*": {"origins": "*"}})
    
    from app.classify import bp as clasify_bp
    app.register_blueprint(clasify_bp, url_prefix='/api/classify')
    
    app.run(debug=False)