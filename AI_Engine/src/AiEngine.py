from flask import Flask,request,jsonify
from pathlib import Path
import joblib
import numpy as np
import os
import re
import sys
import xgboost as xgb
import ember
import lief

sys.modules['numpy._core']=sys.modules.get('numpy._core',np)
sys.modules['numpy._core.multiarray']=sys.modules.get('numpy.core.multiarray',np)
sys.modules['numpy._core.numeric']=sys.modules.get('numpy.core.numeric',np)

if not hasattr(np,'int'): np.int=np.int32
if not hasattr(np,'float'): np.float=np.float64
if not hasattr(np,'bool'): np.bool=np.bool_
if not hasattr(np,'object'): np.object=object

if not hasattr(lief,'bad_format'): lief.bad_format=Exception
if not hasattr(lief,'bad_file'): lief.bad_file=Exception
if not hasattr(lief,'pe_error'): lief.pe_error=Exception
if not hasattr(lief,'parser_error'): lief.parser_error=Exception
if not hasattr(lief,'read_out_of_bound'): lief.read_out_of_bound=Exception
if not hasattr(lief,'builder_error'): lief.builder_error=Exception
if not hasattr(lief,'not_found'): lief.not_found=Exception
if not hasattr(lief,'SECTION_CHARACTERISTICS'): lief.PE.SECTION_CHARACTERISTICS=lief.PE.Section.CHARACTERISTICS

app=Flask(__name__)
BASE_DIR=Path(__file__).resolve().parent
MODEL_DIR=BASE_DIR.parent / 'Models'

print(f"AI models are loading from: {MODEL_DIR}")

xgb_model=cat_model=lgb_model=None

try:
    xgb_model=joblib.load(MODEL_DIR / 'ens_xgb.pkl')
    print("XGBoost model loaded")
except Exception as e:
    print("XGBoost model not loaded")

try:
    cat_model=joblib.load(MODEL_DIR / 'ens_cat.pkl')
    print("Cat model loaded")
except Exception as e:
    print(f"Cat model not loaded: {e}")

try:
    lgb_model=joblib.load(MODEL_DIR / 'ens_lgb.pkl')
    print("LGB model loaded")
except Exception as e:
    print("LGB model not loaded")

#Extracting Ember features

def extract_features_ember(file_path):
    extractor=ember.PEFeatureExtractor(2)
    with open(file_path,'rb') as f:
        bytez=f.read()
    features=np.array(extractor.feature_vector(bytez),dtype=np.float64)
    return features.reshape(1, -1)

#Fallback extractor in case ember fail on a given executable

def extract_features_fallback(file_path):
    #vector_length
    VECTOR_SIZE=2381

    print(f"Forcing Vector Size in fallback mode: {VECTOR_SIZE}")
    feature_vector=np.zeros(VECTOR_SIZE,dtype=np.float64)
    try:
        with open(file_path,'rb') as f:
            bytez=f.read()
        try:
            counts=np.bincount(np.frombuffer(bytez,dtype=np.uint8),minlength=256)
            hist=counts.astype(np.float64)
            if hist.sum() > 0: hist /= hist.sum()
            feature_vector[0:256]=hist
        except Exception:
            pass

        try:
            text=bytez.decode(errors="ignore")
            strings=re.findall(r"[\x20-\x7f]{5,}",text)
            if strings:
                feature_vector[512]=len(strings)
                feature_vector[513]=np.mean([len(s) for s in strings])
        except Exception:
            pass

        try:
            pe=lief.parse(file_path)
            if pe:
                feature_vector[616]=getattr(pe.header,"time_date_stamps",0)
                feature_vector[617]=getattr(pe,"virtual_size",0)
                feature_vector[618]=int(pe.has_debug)
                feature_vector[619]=len(pe.exports) if hasattr(pe,"exports") else 0
                feature_vector[620]=len(pe.imports) if hasattr(pe,"imports") else 0
        except Exception:
            pass

    except Exception as e:
        print(f"Error at extracting fallback features: {e}")

    if cat_model is not None and hasattr(cat_model,'feature_names_'):
        catboost_expected_size=len(cat_model.feature_names)
        if len(feature_vector)<catboost_expected_size:
            print(f"Vector size is too small ({len(feature_vector)}). Padding with zeros with {catboost_expected_size}")
            padding=np.zeros(catboost_expected_size-len(feature_vector),dtype=np.float64)
            feature_vector=np.concatenate((feature_vector,padding))

    return feature_vector.reshape(1,-1)

@app.route('/scan',methods=['POST'])
def predict ():
    try:
        data=request.get_json()
        if not data or 'file_path' not in data:
            return jsonify({"error:Json path not found."}),400

        file_path=data['file_path']
        if not os.path.exists(file_path):
            return jsonify({"error:File not found."}),404

        foloseste_fallback=False

        try:
            vector=extract_features_ember(file_path)
        except Exception as e:
            print(f"Error extracting features: {e}.Executing fallback mode")
            vector=extract_features_fallback(file_path)
            foloseste_fallback=True

        scoruri_valide=[]
        detalii_texte=[]

        if xgb_model is not None:
            xgb_features=xgb.DMatrix(vector)
            pred_xgb=xgb_model.predict(xgb_features)
            prob_xgb=float(pred_xgb[0]) if len(pred_xgb.shape) == 1 else float(pred_xgb[0][1])
            scoruri_valide.append(prob_xgb)
            detalii_texte.append(f"XGB: {prob_xgb*100:.1f}%")

        if cat_model is not None:
            try:
                prob_cat=float(cat_model.predict_proba(vector)[0][1])
            except AttributeError:
                prob_cat=float(cat_model.predict(vector)[0])
            scoruri_valide.append(prob_cat)
            detalii_texte.append(f"Catboost: {prob_cat*100:.1f}%")

        if lgb_model is not None:
            try:
                try:
                    prob_lgb=float(lgb_model.predict_proba(vector)[0][1])
                except AttributeError:
                    prob_lgb=float(lgb_model.predict(vector)[0])
                scoruri_valide.append(prob_lgb)
                detalii_texte.append(f"LGB: {prob_lgb*100:.1f}%")
            except Exception:
                pass

        if not scoruri_valide:
            return jsonify({'error': "No prediction was able to be executed"}),500

        soft_voting_score=sum(scoruri_valide)/len(scoruri_valide)
        confidence_percentage=float(soft_voting_score*100)

        verdict="Malware" if confidence_percentage >=50 else "Safe"

        if foloseste_fallback:
            detalii="Fallback mode" + " | ".join(detalii_texte)
        else:
            detalii=" | ".join(detalii_texte)

        response={
            "verdict":verdict,
            "confidence_score":confidence_percentage,
            "details":detalii
        }
        return jsonify(response),200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error":str(e)}),500

if __name__ == "__main__":
    print("CortexAV Ai Engine is running on port 5000")
    app.run(host="127.0.0.1",port=5000,debug=False)

