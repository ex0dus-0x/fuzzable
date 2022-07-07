"""
ast.py
"""
from tree_sitter import Language, Parser

from . import AnalysisBackend

class AstAnalysis(AnalysisBackend):
    def __init__(self, view):
        self.view = view

    def run(self):
        pass