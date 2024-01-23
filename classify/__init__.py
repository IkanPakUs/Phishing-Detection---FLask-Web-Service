from flask import Blueprint

bp = Blueprint('classify', __name__)

from classify import routes