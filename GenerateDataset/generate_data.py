import pandas as pd
from feature_extraction import Extractor
dataset = pd.read_csv("dataset/chongluadaov2.csv")
urls = dataset["url"].values
extractor = Extractor()
visited = []
result = {}
for url in urls:
    if url in visited:
        continue
    visited.append(url)
    try:
        tempResult = extractor(url)
        result[url] = tempResult
        pd.DataFrame(result.items(), columns=["urls", "features"]).to_csv(
            "chongluadao_datasetV2.csv", index=False)
    except Exception as e:
        print(e)
        continue
