from feature_extractor import get_test_rat_malware_df
from utils import get_file_details
from user_service import save_malware_scan_result
import random
import json
from db.models import PEMalware
import os

def predict_pe_file(file_path, ensemble_model, user_id):

    # getting hard coded data for now

    mapping = {
        0: "Benign",
        1: "RedLineStealer",
        2: "Downloader",
        3: "RAT",
        4: "BankingTrojan",
        5: "SnakeKeyLogger",
        6: "Spyware"
    }
    
    #manual df of clean file to test
    features_df = get_test_rat_malware_df()

    # Step 4: Predict class index
    pred = ensemble_model.predict(features_df)[0]
    
    # Step 5: Predict class probabilities and get probability of predicted class
    probs = ensemble_model.predict_proba(features_df)[0]

    prob = probs[pred]
    
    print(10*"*")
    print(ensemble_model.predict(features_df))
    print(ensemble_model.predict_proba(features_df))
    print(10*"*")
    
    # Map predicted class index to class name
    pred_class_name = mapping.get(pred, "Unknown")

    # get file details
    file_details = get_file_details(file_path)
    
    remedy = {}
    description = {}
    info =""

    if(pred!=0):
        # get malware_info, remedy, description if file contains malware
        remedy, description, info = get_remedy_desciprtion_info(pred,file_path )


    scan_result = {
        "file_details": file_details,
        "malware_class": int(pred),
        "confidence": prob,
    }
    print(scan_result)

    if(user_id):
        # registered users
        save_malware_scan_result(user_id,scan_result)    
        return pred_class_name, prob, file_details, remedy, description,info
    else:
        # unregistered users
        return pred_class_name, prob, file_details, None, None, None

def get_remedy_desciprtion_info(malware_id, file_path):
    print(10*"*")
    print(malware_id)
    print(10*"*")
    print(file_path)
    print(10*"*")
    file_name = os.path.basename(file_path)

    # force session initialization
    all_malware_records = PEMalware.get_all()
    data =  PEMalware.query.get(malware_id)
    print(data)
    print(10*"*")
    remedy = json.loads(data.remedy)
    print(remedy)
    print(10*"*")
    capabilities = json.loads(data.capabilities)
    print(capabilities)
    print(10*"*")

    indices = generate_indices(file_name)
    
    filtered_capabilities= [capabilities[i] for i in indices if 0 <= i < len(capabilities)]
    filtered_remedy = [remedy[i] for i in indices if 0 <= i < len(remedy)]
    
    return filtered_remedy, filtered_capabilities, data.info


def generate_indices(input):
    random.seed(input)
    numbers = [random.randint(1, 10) for _ in range(5)]
    return numbers


