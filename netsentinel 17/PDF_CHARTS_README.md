# PDF chart export

The report generator now includes an Investigation Charts section and a Performance and Security Analysis Charts section. Charts are embedded as native vector drawings in the signed PDF; no Plotly image exporter is required.

To include measurements, run **Run Benchmark**, **Run Detailed Performance Comparison**, and **Run Security Experiments** under Comparison & Reports before selecting **Generate Signed PDF**. Then download the newly generated PDF and its matching `.sig` file. Previously downloaded reports do not change retroactively. Restart the Streamlit server after replacing the project folder so it loads the updated report generator.

If measurements have not been recorded, the PDF explains which charts are unavailable instead of inventing results. The report's benchmark measurements are global and not derived from the selected incident.

Smoke check: A synthetic, explicitly labeled in-memory dataset was used to generate a 6-page PDF with vector charts. This does not replace a full Streamlit/macOS test.
