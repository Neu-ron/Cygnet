import tensorflow as tf
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, OneHotEncoder, MinMaxScaler
from sklearn.model_selection import train_test_split
from keras import backend as K
from sklearn.metrics import mean_squared_error
import pickle
import os
import sys

CURDIR = os.path.dirname(os.path.abspath(sys.argv[0]))
SCALER_PATH = CURDIR+"/assets/scaler.pkl"
TRAIN_PATH = CURDIR+"/datasets/unsw_nb15/UNSW_NB15_training-set.csv"
TEST_PATH = CURDIR+"/datasets/unsw_nb15/UNSW_NB15_testing-set.csv"

categorical_feature = 'proto'
numerical_features = ['spkts', 'dpkts', 'sbytes', 'dbytes', 'smean', 'dmean']

#columns to remove from UNSW-NB15 (features disregarded for this project + labels)
cols_to_remove = ['id', 'dur', 'service', 'state', 'rate', 'sttl', 
                  'dttl', 'sload', 'dload', 'sloss', 'dloss', 
                  'sinpkt', 'dinpkt', 'sjit', 'djit', 'swin', 
                  'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 
                  'ackdat', 'trans_depth', 'response_body_len', 
                  'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 
                  'ct_src_dport_ltm', 'ct_dst_sport_ltm', 
                  'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd', 
                  'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst', 
                  'is_sm_ips_ports', 'attack_cat', 'label']

def get_numericals_categoricals(data):
    numericals = np.zeros((len(data),6), dtype=np.float64)
    categoricals = np.zeros((len(data),2), dtype=np.float64)
    for i in range(len(data)):
        numericals[i]=data[i][0:6]
        categoricals[i]=data[i][6:]
    return numericals, categoricals

def rmse(y_true, y_pred):
    return np.sqrt(np.mean(np.square(y_true-y_pred)))

def prep_data_without_scaling(dpath, malicious_only=True, benign_only=False):
    df = pd.read_csv(dpath)
    if malicious_only:
        df = df[df['label']==1]
    elif benign_only:
        df = df[df['label']==0]
    df = df[df['proto'].isin(['tcp','udp'])]
    x = df.drop(cols_to_remove, axis=1)
    x = pd.get_dummies(x, columns=[categorical_feature])
    res = x.values
    return res  

def scale_data(data, scaler):
    numericals, categoricals = get_numericals_categoricals(data)
    scaled_numericals = scaler.fit_transform(numericals)
    return np.concatenate([scaled_numericals, categoricals], axis=1)

def scale_test_data(data):
    numericals, categoricals = get_numericals_categoricals(data)
    with open(SCALER_PATH, 'rb') as f:
        scaler = pickle.load(f)
    scaled_numericals = scaler.transform(numericals)
    return np.concatenate([scaled_numericals, categoricals], axis=1)

def rescale_data(data):
    numericals, categoricals = get_numericals_categoricals(data)
    with open(SCALER_PATH, 'rb') as f:
        scaler = pickle.load(f)
    rescaled_numericals = scaler.inverse_transform(numericals)
    return np.concatenate([rescaled_numericals, categoricals], axis=1)

def build_autoencoder(input_shape, latent_dim, learning_rate = 0.01):
    K.set_floatx('float64') #setting model layers dtype to float64, matching input
    #encoder
    input_layer = tf.keras.Input(input_shape)
    #adding noise only to the 6 first features which are continuous
    noisy_input = tf.keras.layers.GaussianNoise(stddev=0.2, seed=123)(input_layer[:, :6])
    final_input = tf.keras.layers.concatenate([noisy_input, input_layer[:, 6:]], axis=1)

    x = tf.keras.layers.Dense(4, activation='relu', 
                kernel_regularizer=tf.keras.regularizers.l2(learning_rate))(final_input)
    encoder_outputs = tf.keras.layers.Dense(latent_dim, activation='relu')(x)

    #decoder
    #decoder inputs = encoder outputs
    t = tf.keras.layers.Dense(4, activation='relu', 
                kernel_regularizer=tf.keras.regularizers.l2(learning_rate))(encoder_outputs) 
    decoder_outputs = tf.keras.layers.Dense(input_shape[0], activation='linear')(t)

    autoencoder = tf.keras.Model(input_layer, decoder_outputs)
    autoencoder.compile(optimizer='adam', 
                        loss='mean_squared_error')
    return autoencoder 

def train_autoencoder(autoencoder: tf.keras.Model, train_data, validation_data, epochs, verbose, batch_size):
    early_stopping_clause = tf.keras.callbacks.EarlyStopping(patience=10, restore_best_weights=True)
    autoencoder.fit(
        train_data, train_data,
        epochs=epochs,
        verbose=2,
        batch_size=batch_size,
        validation_data=(validation_data,validation_data),
        shuffle=True,
        callbacks=[early_stopping_clause]
    )

def evaluation(autoencoder: tf.keras.Model, test_data):
    return autoencoder.evaluate(test_data, test_data)

def test_reconstruction(autoencoder: tf.keras.Model, test_data):
    scaled_test = scale_test_data(test_data)
    reconstructed = autoencoder.predict(scaled_test)
    return rmse(scaled_test, reconstructed)

def save_autoencoder(autoencoder: tf.keras.Model, saved_model_path, model_name=None):
    if model_name!=None:
        saved_model_path = saved_model_path+'/'+model_name
    autoencoder.save(saved_model_path)

def load_autoencoder(saved_model_path):
        return tf.keras.models.load_model(saved_model_path)
        
def main(model_name):
    scaler = StandardScaler()
    #cleaning train data
    data = prep_data_without_scaling(TRAIN_PATH, malicious_only=False, benign_only=True)
    #scaling data
    scaled_data = scale_data(data, scaler) 
    with open(SCALER_PATH, 'wb') as f:
        pickle.dump(scaler, f)
    train_data, validation_data = train_test_split(scaled_data, test_size=0.2, random_state=123)
    #cleaning test data
    test_data = prep_data_without_scaling(TEST_PATH, malicious_only=False, benign_only=True)
    autoencoder = build_autoencoder(input_shape=(8,), latent_dim=2, learning_rate=0.01)
    train_autoencoder(
        autoencoder=autoencoder, 
        train_data=train_data,
        validation_data=validation_data, 
        epochs=100, 
        verbose=2, 
        batch_size=64
    )
    #evaluation using reconstructions and scaled test data
    test_loss = evaluation(autoencoder, scale_data(test_data, scaler)) 
    #rmse
    rmse_reconstruction_error = test_reconstruction(autoencoder, test_data)
    print(f"test loss: {test_loss}\nRMSE: {rmse_reconstruction_error}")
    #saving the model
    inp = input("Save model? y/n\n")
    if inp.lower()=='y':
        save_autoencoder(
            autoencoder=autoencoder,
            saved_model_path=f"{CURDIR}/assets/dae_saved_model/{model_name}"
        )

if __name__=="__main__":
    main(model_name="dae3")