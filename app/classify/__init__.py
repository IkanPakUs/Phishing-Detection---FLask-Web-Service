from flask import Blueprint

bp = Blueprint('classify', __name__)

from app.classify import routes