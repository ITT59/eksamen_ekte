const express = require("express");
const path = require("path");
const http = require("http");
const sqlite3 = require("sqlite3").verbose();
const session = require("express-session");
const bcrypt = require("bcrypt");

const app = express();
const port = 3000;
const server = http.createServer(app);

/** Serverer statiske filer fra public-mappen */
app.use(express.static(path.join(__dirname, "public")));

/** Middleware for å tolke JSON- og URL-kodet data */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/** Konfigurerer sesjonshåndtering */
app.use(
    session({
        secret: "hemmeligNøkkel",
        resave: false,
        saveUninitialized: true,
        cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 },
    })
);

function isAuthenticated(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        res.redirect("/login");
    }
}

/** Kobler til SQLite-database */
const db = new sqlite3.Database("minNyeDatabase.db", (err) => {
    if (err) {
        console.error("Feil ved tilkobling til database:", err.message);
    } else {
        console.log("Koblet til SQLite-database.");
    }
});

/** Rute: Viser forsiden (kun for autentiserte brukere) */
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "view", "index.html"));
});

/** Rute: Viser innloggingssiden */
app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, "view", "login.html"));
});

/** Rute: Viser siden for å opprette ny bruker */
app.get("/ny-bruker", (req, res) => {
    res.sendFile(path.join(__dirname, "view", "ny-bruker.html"));
});

/** Rute: Viser privat side (kun for autentiserte brukere) */
app.get("/privat", isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, "view", "privat.html"));
});

/** Rute: Logger ut brukeren og avslutter sesjonen */
app.get("/logout", (req, res) => {
    req.session.destroy();
    res.clearCookie("connect.sid");
    res.redirect("/login");
});

/**
 * Rute: Håndterer innlogging
 * Sjekker epost og passord mot databasen
 */
app.post("/login", (req, res) => {
    const { epost, passord } = req.body;
    if (!epost || !passord) {
        return res.redirect("/login?error=Mangler data fra skjema");
    }
    const sql = "SELECT * FROM Bruker WHERE Epost = ?";
    db.get(sql, [epost], async (err, row) => {
        if (err) {
            console.error("Databasefeil:", err.message);
            return res.redirect("/login?error=En uventet feil har oppstått");
        }
        if (row && (await bcrypt.compare(passord, row.Passord))) {
            req.session.user = {
                id: row.ID_bruker,
                navn: row.Navn,
                epost: row.Epost
            };
            res.redirect("/");
        } else {
            res.redirect("/login?error=Ugyldig epost eller passord");
        }
    });
});

/**
 * Rute: Håndterer registrering av ny bruker
 * Lagrer brukeren i databasen med kryptert passord
 */
app.post("/ny-bruker", async (req, res) => {
    const { epost, navn, passord } = req.body;
    if (!epost || !passord || !navn) {
        return res.redirect("/login?error=Mangler data fra skjema");
    }
    const sql = "INSERT INTO Bruker (Navn, Epost, Passord) VALUES (?, ?, ?)";
    const hashedPassword = await bcrypt.hash(passord, 10);
    db.run(sql, [navn, epost, hashedPassword], function (err) {
        if (err) {
            console.error("Databasefeil:", err.message);
            return res.redirect("/login?error=En uventet feil har oppstått");
        }
        req.session.user = { id: this.lastID, navn, epost };
        res.redirect("/?melding=Bruker opprettet");
    });
});

/** Starter serveren */
server.listen(port, () => {
    console.log(`Server kjører på http://localhost:${port}`);
});
