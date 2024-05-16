import tensorflow_decision_forests as tfdf
import tensorflow as tf
import pandas as pd
import os

from flask import current_app as app

class Model:
    model = None
    
    def __init__(self) -> None:
        model_path = 'GBDT'
        real_path = os.path.join(app.root_path, 'model/' + model_path)
        self.model = tf.keras.models.load_model(real_path)
        
    def predict(self, feature):
        pd_feature = pd.DataFrame([feature])
        tfdf_feature = tfdf.keras.pd_dataframe_to_tf_dataset(pd_feature)
        
        return self.model.predict(tfdf_feature)
