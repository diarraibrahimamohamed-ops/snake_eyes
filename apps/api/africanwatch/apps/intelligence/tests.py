from django.test import SimpleTestCase
from .classifier import classify_text, reliability_grade
class IntelligenceClassifierTests(SimpleTestCase):
    def test_multilingual_triage(self):
        result=classify_text("Ransomware cyberattack breach")
        self.assertGreater(result["cyber_signal"], 0)
    def test_reliability_grade(self):
        grade,score=reliability_grade(0.9,3,None)
        self.assertEqual(grade,"A")
