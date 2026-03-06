from tensorflow import keras
from tensorflow.keras import layers # type: ignore

class ChatThreatModel:
    def build(self, vocab_size=5000):
        model = keras.Sequential([
            layers.Embedding(vocab_size, 128),
            layers.LSTM(128, return_sequences=True),
            layers.LSTM(64),
            layers.Dense(1, activation="sigmoid")
        ])

        model.compile(
            optimizer="adam",
            loss="binary_crossentropy",
            metrics=["accuracy"]
        )
        return model

