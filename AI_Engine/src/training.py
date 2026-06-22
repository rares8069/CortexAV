import xgboost as xgb
import lightgbm as lgb
from catboost import CatBoostClassifier, Pool
import numpy as np
import ember
import joblib
import os
import gc
from sklearn.metrics import accuracy_score, roc_auc_score

if __name__ == '__main__':
    data_dir = r"E:\Licenta\ember_data\ember2018"
    models_dir = r"E:\Licenta\models"
    if not os.path.exists(models_dir):
        os.makedirs(models_dir)


    X_train, y_train, X_test, y_test = ember.read_vectorized_features(data_dir)

    X_train = X_train.astype(np.float32)
    X_test = X_test.astype(np.float32)

    train_mask = (y_train != -1)
    X_train, y_train = X_train[train_mask], y_train[train_mask]
    test_mask = (y_test != -1)
    X_test, y_test = X_test[test_mask], y_test[test_mask]


    split_index = -100000
    X_train_final, y_train_final = X_train[:split_index], y_train[:split_index]
    X_val, y_val = X_train[split_index:], y_train[split_index:]


    del X_train, y_train
    gc.collect()


    predictii_test = []

    print("\n=== FAZA 2: ANTRENAMENT XGBOOST (GPU) ===")
    dtrain_xgb = xgb.DMatrix(X_train_final, label=y_train_final)
    dval_xgb = xgb.DMatrix(X_val, label=y_val)
    dtest_xgb = xgb.DMatrix(X_test)

    params_xgb = {
        'objective': 'binary:logistic',
        'eval_metric': 'auc',
        'tree_method': 'hist',
        'device': 'cuda',
        'learning_rate': 0.02,
        'max_depth': 8,
        'subsample': 0.8
    }

    model_xgb = xgb.train(
        params=params_xgb, dtrain=dtrain_xgb, num_boost_round=10000,
        evals=[(dtrain_xgb, 'train'), (dval_xgb, 'eval')],
        early_stopping_rounds=300, verbose_eval=100
    )


    joblib.dump(model_xgb, os.path.join(models_dir, 'ens_xgb.pkl'))
    predictii_test.append(model_xgb.predict(dtest_xgb))


    del model_xgb, dtrain_xgb, dval_xgb, dtest_xgb
    gc.collect()

    print("\n=== FAZA 3: ANTRENAMENT CATBOOST (GPU) ===")
    pool_train = Pool(X_train_final, y_train_final)
    pool_val = Pool(X_val, y_val)

    model_cat = CatBoostClassifier(
        iterations=10000,
        learning_rate=0.03,
        depth=8,
        task_type='GPU',
        eval_metric='AUC',
        early_stopping_rounds=300,
        verbose=100
    )

    model_cat.fit(pool_train, eval_set=pool_val)

    joblib.dump(model_cat, os.path.join(models_dir, 'ens_cat.pkl'))

    predictii_test.append(model_cat.predict_proba(X_test)[:, 1])

    del model_cat, pool_train, pool_val
    gc.collect()

    print("\n=== FAZA 4: ANTRENAMENT LIGHTGBM (CPU - Stabil si Sigur) ===")
    lgb_train = lgb.Dataset(X_train_final, y_train_final)
    lgb_val = lgb.Dataset(X_val, y_val, reference=lgb_train)

    params_lgb = {
        'objective': 'binary',
        'metric': 'auc',
        'device': 'cpu',
        'n_jobs': -1,
        'learning_rate': 0.02,
        'num_leaves': 1024
    }

    model_lgb = lgb.train(
        params_lgb, lgb_train, num_boost_round=10000,
        valid_sets=[lgb_val], callbacks=[lgb.early_stopping(300), lgb.log_evaluation(100)]
    )

    joblib.dump(model_lgb, os.path.join(models_dir, 'ens_lgb.pkl'))
    predictii_test.append(model_lgb.predict(X_test))

    del model_lgb, lgb_train, lgb_val
    gc.collect()



    predictii_medii = (predictii_test[0] + predictii_test[1] + predictii_test[2]) / 3.0


    y_pred_ensemble_label = np.round(predictii_medii)

    accuracy = accuracy_score(y_test, y_pred_ensemble_label)
    auc = roc_auc_score(y_test, predictii_medii)

    print(f"\n**********************************************")
    print(f" REZULTATE FINALE ENSEMBLE (Test Set Complet Nou):")
    print(f" Acuratete: {accuracy * 100:.3f}%")
    print(f" AUC-ROC:   {auc:.5f}")
    print(f"**********************************************")