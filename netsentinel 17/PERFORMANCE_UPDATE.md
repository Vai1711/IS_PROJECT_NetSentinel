# Performance comparison update

Added four measured charts in **Comparison & Reports > Performance**, after the original benchmark:

1. Grouped execution-time bar chart across 1 KB, 10 KB, 100 KB, 1 MB, and 10 MB.
2. Horizontal bulk throughput comparison (SHA-256 and HMAC-SHA256; RSA signing rate reported separately).
3. CPU and Python-tracked peak memory heatmaps with original units in each cell.
4. Multi-line scalability chart comparing all three algorithms.

Click **Run Detailed Performance Comparison** to generate fresh measurements. Existing security analyses and reports remain unchanged.

## Measurement interpretation

- CPU percentage = process CPU time divided by elapsed time, as a percentage of one core. This is not system-wide CPU utilization.
- Memory = peak Python allocations captured by tracemalloc, not total process memory or native-library memory.
- RSA-PSS timing includes SHA-256 hashing of the entire input and is **not** RSA encryption throughput.
- Repeated measurements are summarized by their median; charts use real measurements, not hardcoded values.

### Heatmap refinement (Nov 2026)
CPU and peak Python-tracked memory heatmaps now use a pale-blue-to-navy palette, visible cell gaps, and a nonlinear log1p color mapping with a labeled color scale. Displayed measurements remain unchanged. This improves visibility of small values when one outlier dominates the range.
