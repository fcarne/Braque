package ui;

import static spark.Spark.*;

public class BraqueApp {
    public static void main(String[] args) {
        get("/", (req, res) -> "Hello World");
    }
}

