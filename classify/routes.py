from classify import bp
from flask import request
from flask_cors import cross_origin
from .services.Extract import Extract
from .services.Model import Model


@bp.after_request
def after_request(response):
    header = response.headers
    
    header['Access-Control-Allow-Origin'] = '*'
    header['Access-Control-Allow-Headers'] = 'Content-Type'
        
    return response

@bp.route('/', methods=['POST'], strict_slashes=False)
@cross_origin()
def classify():
    print(request.headers)
    req = request.json
    
    extract = Extract(req['website_uri'])
    feature = extract.extractFeature()
    
    model = Model()
    prediction = model.predict(feature)
    
    phishing_possibility = prediction[0][0]

    return {
        'is_phishing': True if phishing_possibility > .5 else False,
        'score': str(phishing_possibility),
    }