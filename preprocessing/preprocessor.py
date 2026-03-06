import re
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.sentiment import SentimentIntensityAnalyzer

stop_words = set(stopwords.words("english"))
sentiment = SentimentIntensityAnalyzer()

def clean_text(text: str):
    text = text.lower()
    text = re.sub(r"<.*?>", "", text)
    text = re.sub(r"[^a-zA-Z ]", "", text)

    tokens = word_tokenize(text)
    tokens = [t for t in tokens if t not in stop_words]

    sentiment_score = sentiment.polarity_scores(text)["compound"]
    return " ".join(tokens), sentiment_score
