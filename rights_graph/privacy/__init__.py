"""Differentially private aggregate delivery.

This package implements pure epsilon differential privacy with the Laplace
mechanism.  The protected unit is always a single subject (identified by a
stable subject key); adding or removing one subject is the adjacency relation,
and a subject may appear in many rows and across several frozen data versions.
Contribution caps bound how much one subject can move every released vector.
"""
