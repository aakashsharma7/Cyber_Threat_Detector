import sys
import os
import logging
from pathlib import Path

# Add the project root to Python path
project_root = str(Path(__file__).parent.parent.parent)
sys.path.append(project_root)

from app.ml.threat_detector import ThreatDetector
from app.core.config import settings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_model_loading():
    """Test if the model can be loaded"""
    logger.info("Testing model loading...")
    try:
        detector = ThreatDetector(settings.MODEL_PATH)
        if detector.model is not None:
            logger.info("✅ Model loaded successfully")
            return True
        else:
            logger.warning("⚠️ Model is None after loading")
            return False
    except Exception as e:
        logger.error(f"❌ Error loading model: {str(e)}")
        return False

def test_prediction():
    """Test model predictions with sample data"""
    logger.info("\nTesting model predictions...")
    try:
        detector = ThreatDetector(settings.MODEL_PATH)
        
        # Sample feature data
        sample_features = {
            "request_count": 10,
            "failed_login_attempts": 3,
            "unique_ips": 2,
            "request_rate": 5.0,
            "url_length": 50,
            "has_suspicious_patterns": 1,
            "is_known_bad_ip": 0,
            "time_since_last_request": 60
        }
        
        # Make prediction
        prediction = detector.predict(sample_features)
        
        # Log results
        logger.info("Sample prediction results:")
        logger.info(f"Threat Probability: {prediction['threat_probability']:.2%}")
        logger.info(f"Is Threat: {prediction['is_threat']}")
        logger.info("Feature Importances:")
        for feature, importance in prediction['feature_importances'].items():
            logger.info(f"  - {feature}: {importance:.4f}")
        
        return True
    except Exception as e:
        logger.error(f"❌ Error making prediction: {str(e)}")
        return False

def test_model_training():
    """Test if the model can be trained"""
    logger.info("\nTesting model training...")
    try:
        import numpy as np
        import pandas as pd
        
        # Create sample training data
        X = pd.DataFrame({
            "request_count": np.random.randint(0, 100, 100),
            "failed_login_attempts": np.random.randint(0, 10, 100),
            "unique_ips": np.random.randint(1, 5, 100),
            "request_rate": np.random.uniform(0, 10, 100),
            "url_length": np.random.randint(10, 200, 100),
            "has_suspicious_patterns": np.random.randint(0, 2, 100),
            "is_known_bad_ip": np.random.randint(0, 2, 100),
            "time_since_last_request": np.random.randint(0, 3600, 100)
        })
        y = np.random.randint(0, 2, 100)  # Binary labels
        
        # Create and train model
        detector = ThreatDetector()
        detector.train(X, y)
        
        logger.info("✅ Model training successful")
        return True
    except Exception as e:
        logger.error(f"❌ Error training model: {str(e)}")
        return False

def main():
    """Run all tests"""
    logger.info("Starting ML model tests...")
    
    # Test model loading
    if not test_model_loading():
        logger.error("Model loading test failed")
        return
    
    # Test predictions
    if not test_prediction():
        logger.error("Prediction test failed")
        return
    
    # Test model training
    if not test_model_training():
        logger.error("Model training test failed")
        return
    
    logger.info("\n✅ All tests completed successfully!")

if __name__ == "__main__":
    main() 