import tensorflow_decision_forests as tfdf
import tensorflow as tf
import pandas as pd
import os

from flask import current_app as app

class Model:
    model = None
    
    def __init__(self) -> None:
        model_path = 'ANN'
        real_path = os.path.join(app.root_path, 'model/' + model_path)
        self.model = tf.keras.models.load_model(real_path)
        
    def predict(self, feature):
        pd_feature = pd.DataFrame([feature])
        
        return self.model.predict(pd_feature)
