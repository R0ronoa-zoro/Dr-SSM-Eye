"""
Classification and Feature Aggregation Module
Aggregates features and performs classification
"""

import logging
from typing import Dict, Any, List, Tuple
import os
import pickle

from core.data_models import ModuleResult

logger = logging.getLogger('dr_ssm_eye')


class Classifier:
    """Feature aggregation and classification"""
    
    def __init__(self):
        self.ml_model = self._load_ml_model()
        self.logger = logging.getLogger('dr_ssm_eye')
    
    def _load_ml_model(self):
        """Load trained ML model if exists"""
        model_path = "models/xgboost_classifier.pkl"
        
        if os.path.exists(model_path):
            try:
                with open(model_path, 'rb') as f:
                    model = pickle.load(f)
                logger.info("ML model loaded successfully")
                return model
            except Exception as e:
                logger.warning(f"Failed to load ML model: {e}")
                return None
        else:
            logger.warning("ML model not found, using rule-based classification only")
            return None
    
    def aggregate_features(self, module_results: List[ModuleResult]) -> Dict[str, Any]:
        """
        Aggregate all module results into feature vector
        
        Args:
            module_results: List of ModuleResult objects
        
        Returns:
            Dictionary of aggregated features
        """
        features = {}
        
        for result in module_results:
            if result and result.features:
                for key, value in result.features.items():
                    feature_key = f"{result.module_name}_{key}"
                    features[feature_key] = value
        
        url_features = self._extract_url_features(module_results)
        features.update(url_features)
        
        return features
    
    def _extract_url_features(self, module_results: List[ModuleResult]) -> Dict[str, Any]:
        """Extract URL-based features"""
        features = {}
        
        url = ""
        for result in module_results:
            if result and result.features and result.features.get('url'):
                url = result.features.get('url', '')
                break
        
        if url:
            features['url_length'] = len(url)
            features['has_ip_address'] = self._has_ip_in_url(url)
            features['has_at_symbol'] = '@' in url
            features['hyphen_count'] = url.count('-')
            features['subdomain_count'] = url.count('.') - 1
        else:
            features['url_length'] = 0
            features['has_ip_address'] = False
            features['has_at_symbol'] = False
            features['hyphen_count'] = 0
            features['subdomain_count'] = 0
        
        threat_result = self._find_module(module_results, "threat_intel")
        if threat_result and threat_result.features:
            features['in_threat_database'] = threat_result.features.get('threat_found', False)
        else:
            features['in_threat_database'] = False
        
        whitelist_result = self._find_module(module_results, "whitelist")
        if whitelist_result and whitelist_result.features:
            tier = whitelist_result.features.get('tier', 'none')
            features['in_tranco_top_10k'] = tier == 'top_10k'
            features['in_tranco_top_100k'] = tier in ['top_10k', 'top_100k']
        else:
            features['in_tranco_top_10k'] = False
            features['in_tranco_top_100k'] = False
        
        whois_result = self._find_module(module_results, "whois")
        if whois_result and whois_result.features:
            features['domain_age_days'] = whois_result.features.get('domain_age_days', 999)
        else:
            features['domain_age_days'] = None
        
        ssl_result = self._find_module(module_results, "ssl")
        if ssl_result and ssl_result.features:
            features['has_https'] = ssl_result.features.get('has_https', False)
        else:
            features['has_https'] = False
        
        content_result = self._find_module(module_results, "content")
        if content_result and content_result.features:
            features['has_password_field'] = content_result.features.get('has_password_field', False)
        else:
            features['has_password_field'] = False
        
        return features
    
    def _has_ip_in_url(self, url: str) -> bool:
        """Check if URL contains IP address"""
        import re
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return bool(re.search(ip_pattern, url))
    
    def _find_module(self, module_results: List[ModuleResult], module_name: str) -> ModuleResult:
        """Find module result by name"""
        if not module_results:
            return None
        
        for result in module_results:
            if result and result.module_name == module_name:
                return result
        return None
    
    def calculate_risk_score(
        self,
        features: Dict[str, Any],
        module_results: List[ModuleResult]
    ) -> int:
        """
        Calculate weighted risk score
        
        Args:
            features: Aggregated features
            module_results: List of module results
        
        Returns:
            Risk score (-100 to +200)
        """
        score = 0
        
        if not module_results:
            return 0
        
        for result in module_results:
            if result and result.risk_contribution is not None:
                score += result.risk_contribution
        
        score = max(-100, min(200, score))
        
        return score
    
    def classify_by_score(self, risk_score: int, confidence: float) -> str:
        """
        Map risk score to classification
        
        Args:
            risk_score: Risk score
            confidence: Confidence value
        
        Returns:
            Classification string
        """
        if confidence < 0.60:
            return "ANALYST_REQUIRED"
        
        if risk_score < -20:
            return "CLEAN"
        elif risk_score <= 40:
            return "SUSPICIOUS"
        else:
            return "MALICIOUS"
    
    def ml_classify(self, features: Dict[str, Any]) -> Tuple[str, float]:
        """
        Machine learning classification
        
        Args:
            features: Feature dictionary
        
        Returns:
            Tuple of (classification, confidence)
        """
        if self.ml_model is None:
            return None, 0.0
        
        try:
            feature_vector = self._prepare_feature_vector(features)
            
            probabilities = self.ml_model.predict_proba([feature_vector])[0]
            
            predicted_class_idx = probabilities.argmax()
            confidence = probabilities[predicted_class_idx]
            
            class_map = {0: "CLEAN", 1: "SUSPICIOUS", 2: "MALICIOUS"}
            predicted_class = class_map.get(predicted_class_idx, "SUSPICIOUS")
            
            return predicted_class, confidence
        
        except Exception as e:
            logger.error(f"ML classification error: {e}")
            return None, 0.0
    
    def _prepare_feature_vector(self, features: Dict[str, Any]) -> List[float]:
        """Prepare feature vector for ML model"""
        expected_features = [
            'url_length', 'subdomain_count', 'has_ip_address', 'has_at_symbol',
            'hyphen_count', 'in_threat_database', 'in_tranco_top_10k',
            'domain_age_days', 'has_https', 'has_password_field'
        ]
        
        vector = []
        for feature_name in expected_features:
            value = features.get(feature_name, 0)
            
            if value is None:
                value = 0
            elif isinstance(value, bool):
                value = 1 if value else 0
            elif not isinstance(value, (int, float)):
                value = 0
            
            vector.append(float(value))
        
        return vector
    
    def classify(
        self,
        features: Dict[str, Any],
        module_results: List[ModuleResult],
        risk_score: int
    ) -> Tuple[str, float]:
        """
        Perform classification combining rule-based and ML
        
        Args:
            features: Aggregated features
            module_results: List of module results
            risk_score: Calculated risk score
        
        Returns:
            Tuple of (classification, confidence)
        """
        if self.ml_model is not None:
            ml_class, ml_conf = self.ml_classify(features)
            
            if ml_class:
                rule_class = self.classify_by_score(risk_score, 0.8)
                
                if ml_class == rule_class:
                    return ml_class, ml_conf
                else:
                    confidence = min(ml_conf, 0.7)
                    return ml_class, confidence
        
        rule_class = self.classify_by_score(risk_score, 0.8)
        
        if risk_score < -50:
            confidence = 0.95
        elif risk_score < -20:
            confidence = 0.85
        elif risk_score < 0:
            confidence = 0.75
        elif risk_score < 40:
            confidence = 0.70
        elif risk_score < 80:
            confidence = 0.85
        else:
            confidence = 0.95
        
        return rule_class, confidence