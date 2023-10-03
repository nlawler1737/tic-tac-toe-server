const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");

const cors = require("cors");
const mysql = require("mysql2/promise");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const crypto = require("crypto");

require("dotenv").config();

const responseBuilder = require("./utils/responseBuilder");
const { match } = require("assert");

const port = process.env.PORT;
const socketPort = process.env.SOCKET_PORT;
// default port to listen
const app = express();

const socketServer = express();
const server = http.createServer(app);
const io = new Server(server);

const connectedSockets = new Map();

const corsOptions = {
    origin: "*",
    credentials: true, //access-control-allow-credentials:true
    optionSuccessStatus: 200,
};

// console.log({
//     host: process.env.DB_HOST,
//     user: process.env.DB_USER,
//     password: process.env.DB_PASSWORD,
//     database: process.env.DB_NAME,
// });

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

const verifyJwtFromSocket = (token) => {
    try {
        const payload = jwt.verify(token, process.env.JWT_KEY);
        return { data: payload };
    } catch (err) {
        return { error: err.message };
    }
};

app.use(cors(corsOptions));

app.use(bodyParser.json());

io.on("connection", (socket) => {
    console.log("socket connected");
    const {
        handshake: {
            query: { referringPath },
            auth,
        },
    } = socket;

    const payload = verifyJwtFromSocket(auth.token);

    if (payload.error) {
        socket.disconnect();
        return;
    }

    socket.userId = payload.data.userId;
    connectedSockets.set(payload.data.userId, {
        socket,
        opponentSocket: null,
        opponentId: null,
    });

    socket.on("disconnect", () => {
        console.log("user disconnected");
        connectedSockets.delete(payload.data.userID);
    });
});

app.use(express.static(path.join(__dirname, "dist")));

app.use((err, req, res, next) => {
    res.status(500).send(err);
    next();
});

const connectDatabase = async (req, res, next) => {
    try {
        req.db = await pool.getConnection();
        req.db.connection.config.namedPlaceholders = true;

        // Traditional mode ensures not null is respected for unsupplied fields, ensures valid JavaScript dates, etc.
        await req.db.query('SET SESSION sql_mode = "TRADITIONAL"');
        await req.db.query(`SET time_zone = '-8:00'`);

        await next();

        req.db.release();
    } catch (err) {
        // If anything downstream throw an error, we must release the connection allocated for the request
        console.error("Error - connecting database", err.message);
        if (req.db) req.db.release();
        throw err;
    }
};

const attachCurrentGame = async (req, res, next) => {
    const { user } = req;

    try {
        const [matchedUsers] = await req.db.query(
            `
            SELECT (current_game) FROM users
            WHERE id = :userId AND current_game IS NOT NULL
            `,
            {
                userId: user.userId,
            }
        );
        const gameId = matchedUsers[0]?.current_game || undefined;
        if (gameId === undefined || gameId === null) {
            req.currentGame = null;
            next();
            return;
        }
        const [[game]] = await req.db.query(
            `
            SELECT * FROM games
            WHERE id = :gameId;
        `,
            {
                gameId,
            }
        );

        const user1_socket = connectedSockets.get(game.user1_id);
        const user2_socket = connectedSockets.get(game.user2_id);

        if (user1_socket && user2_socket) {
            connectedSockets.set(game.user_id, {
                ...user1_socket,
                opponentSocket: user2_socket.socket,
                opponentId: game.user2_id,
                gameId: game.id,
            });
            connectedSockets.set(game.user2_id, {
                ...user2_socket,
                opponentSocket: user1_socket.socket,
                opponentId: game.user1_id,
                gameId: game.id,
            });
            game.user1_socket = user1_socket;
            game.user2_socket = user2_socket;
        }

        req.currentGame = game;

        next();
    } catch (err) {
        console.error("Error - attaching game to user", err.message);
        next();
    }
};

app.post("/register", connectDatabase, async function (req, res) {
    try {
        let encodedUser;
        let resError;

        // Hashes the password and inserts the info into the `user` table
        await bcrypt.hash(req.body.password, 10).then(async (hash) => {
            try {
                const [user] = await req.db.query(
                    `
                    INSERT INTO users (username, password)
                    VALUES (:username, :password);
                    `,
                    {
                        // email: req.body.email,
                        username: req.body.username,
                        password: hash,
                    }
                );

                encodedUser = jwt.sign(
                    {
                        userId: user.insertId,
                        ...req.body,
                    },
                    process.env.JWT_KEY
                );
            } catch (err) {
                resError = err;
                console.error("Error - hashing password", err.message);
            }
        });

        if (resError) {
            if (resError.code === "ER_DUP_ENTRY")
                res.json(
                    responseBuilder({ msg: "Username Already Exists" }, true)
                );
        } else res.json(responseBuilder({ jwt: encodedUser }, false));
    } catch (err) {
        console.error("Error - registering user", err.message);
        res.json(responseBuilder({ msg: "Error Occurred Try Again" }, true));
    }
});

app.post("/authenticate", connectDatabase, async function (req, res) {
    try {
        const { username, password } = req.body;

        const [[user]] = await req.db.query(
            `SELECT * FROM users WHERE username = :username`,
            { username }
        );

        if (!user) res.json(responseBuilder({ msg: "Email not found" }, true));

        const dbPassword = `${user.password}`;
        const compare = await bcrypt.compare(password, dbPassword);

        if (compare) {
            const payload = {
                userId: user.id,
                username: user.user_name,
            };

            const encodedUser = jwt.sign(payload, process.env.JWT_KEY);

            res.json(responseBuilder({ jwt: encodedUser, id:user.id }, false));
        } else {
            res.json(responseBuilder({ msg: "Password not found" }, true));
        }
    } catch (err) {
        console.error("Error - authenticating user", err.message);
    }
});

// Jwt verification checks to see if there is an authorization header with a valid jwt in it.
const verifyJwt = async (req, res, next) => {
    if (!req.headers.authorization) {
        res.redirect("/login");
        next("Invalid authorization, no authorization headers");
        return;
    }

    const [scheme, token] = req.headers.authorization.split(" ");
    if (scheme !== "Bearer") {
        next("Invalid authorization, invalid authorization scheme");
        return;
    }

    try {
        const payload = jwt.verify(token, process.env.JWT_KEY);

        req.user = payload;
    } catch (err) {
        console.error("Error - verifying jwt", err.message);
        if (
            err.message &&
            (err.message.toUpperCase() === "INVALID TOKEN" ||
                err.message.toUpperCase() === "JWT EXPIRED")
        ) {
            req.body = err.message;
            await next();
        } else {
            next(err.status || 500, err.message);
        }
    }

    await next();
};

app.get("/user/:userId", connectDatabase, async (req, res) => {
    console.log("user GET");

    const { params } = req;

    const gameTotals = await getGameTotals();
    const gameHistory = await getGameHistory();

    if (gameTotals.status === "error") {
        res.json(responseBuilder({msg: gameTotals.value},true))
    }
    if (gameHistory.status === "error") {
        res.json(responseBuilder({msg: gameHistory.value},true))
    }
    // console.log(gameHistory.value, gameTotals.value)
    if (!gameHistory.value.length) res.json(responseBuilder({msg:"no games played", data: {history: [], totals: {}}}))
    else res.json(responseBuilder({ msg: "user data received", data: {history: gameHistory.value, totals: gameTotals.value} }, false));

    async function getGameHistory() {
        try {
            const [results] = await req.db.query(`
            SELECT user1_id as player_1, user2_id as player_2, winner, game_type, start_time, end_time FROM games
            WHERE user1_id = :user_id OR user2_id = :user_id
            `, {
                user_id: params.userId
            })
            return {status: "success", value: results}
        } catch (err) {
            console.error("Error - getting game history")
            return {status: "error", value: err.message}
        }
    }

    async function getGameTotals() {
        try {
            const [[results]] = await req.db.query(
                `
            SELECT
                u.id,
                u.username,
                SUM(CASE WHEN g.winner = u.id THEN 1 ELSE 0 END) AS wins,
                SUM(CASE WHEN g.winner != -1 AND g.winner != u.id THEN 1 ELSE 0 END) AS losses,
                SUM(CASE WHEN g.winner = -1 THEN 1 ELSE 0 END) AS draws,
                COUNT(CASE WHEN g.winner IS NOT NULL THEN 1 ELSE 0 END) AS total_games_played
            FROM users u
            LEFT JOIN games g ON u.id = g.user1_id OR u.id = g.user2_id
            WHERE u.id = :user_id AND g.winner IS NOT NULL
            GROUP BY u.id, u.username;
            `,
                {
                    user_id: params.userId,
                }
            );
            
            return {status: "success", value: results,}
        } catch (err) {
            console.error("Error - getting user totals", err.message);
            return {status: "error", value: err.message}
        }
    }
});

app.post(
    "/join-queue",
    connectDatabase,
    verifyJwt,
    attachCurrentGame,
    async (req, res) => {
        // check if user is already in game => res "already in game" => exit
        // add user to queue
        // check for opponent in queue
        // create game
        // remove both users from queue
        // res "game starting"
        // ping both sockets to start game
        console.log("join-queue");
        const { user, currentGame } = req;

        const game_type = 0;

        if (currentGame !== null) {
            res.json(
                responseBuilder({ code: 1, msg: "already in game" }, true)
            );
            return;
        }

        const userInQueue = await addUserToQueue();

        if (userInQueue.status === "error") {
            res.json(
                responseBuilder({ code: 0, msg: userInQueue.value }, true)
            );
            return;
        }

        const opponentInQueue = await getFirstOpponentFromQueue();

        if (opponentInQueue.status === "error") {
            res.json(
                responseBuilder({ code: 0, msg: opponentInQueue.value }, true)
            );
            return;
        } else if (opponentInQueue.status === "failed") {
            res.json(
                responseBuilder(
                    { code: 2, msg: "Waiting for Opponent..." },
                    false
                )
            ); // no opponent
            return;
        }

        const opponent = opponentInQueue.value;

        const game = await createGame(
            req.db,
            [user.userId, opponent.user_id],
            game_type
        );

        res.json(
            responseBuilder(
                { code: 3, msg: "Game Starting...", status: true },
                false
            )
        );

        updatePlayersSocketsMap(...game.value);

        /**
         *
         * @returns {{ status: "success" | "failed" | true, value: object }} value: opponent
         */
        async function getFirstOpponentFromQueue() {
            try {
                const [nextPlayer] = await req.db.query(
                    `
            SELECT * FROM queue
            WHERE user_id != :user_id
            AND game_type = :game_type
            LIMIT 1;`,
                    {
                        user_id: user.userId,
                        game_type,
                    }
                );

                if (!nextPlayer.length) {
                    return { status: "failed", value: "no opponents found" }; // no opponent found
                }

                return { status: true, value: nextPlayer[0] }; // opponent found
            } catch (err) {
                console.error("Error - match err: ", err.message);
                return { status: "error", value: err.message };
            }
        }

        async function createGame(db, playerIds, gameType) {
            const rand = Math.random() >= 0.5 ? [0, 1] : [1, 0];
            const player1 = playerIds[rand[0]];
            const player2 = playerIds[rand[1]];

            try {
                const [game] = await db.query(
                    `
            INSERT INTO games (user1_id, user2_id, game_type, game_state)
            VALUES (:user1_id, :user2_id, :game_type, :game_state)`,
                    {
                        user1_id: player1,
                        user2_id: player2,
                        game_type: gameType,
                        game_state: JSON.stringify(Array(9).fill(null)),
                    }
                );

                await removePlayersFromQueue();

                await db.query(
                    `
            UPDATE users
            SET current_game = :game_id
            WHERE id = :user1_id OR id = :user2_id;
            `,
                    {
                        game_id: game.insertId,
                        user1_id: player1,
                        user2_id: player2,
                    }
                );

                return {
                    status: "success",
                    value: [game.insertId, player1, player2],
                };
            } catch (err) {
                console.error("Error - create game", err.message);
                return { status: "error", value: err.message };
            }

            async function removePlayersFromQueue() {
                try {
                    await db.query(
                        `
                    DELETE FROM queue
                    WHERE user_id = :user1_id OR user_id = :user2_id
                `,
                        {
                            user1_id: player1,
                            user2_id: player2,
                        }
                    );
                } catch (err) {
                    console.error(
                        "Error - remove players from queue: ",
                        err.message
                    );
                }
            }
        }

        function updatePlayersSocketsMap(gameId, user1_id, user2_id) {
            const user1_socket = connectedSockets.get(user1_id) || {};
            const user2_socket = connectedSockets.get(user2_id) || {};

            connectedSockets.set(user1_id, {
                ...user1_socket,
                opponentSocket: user2_socket.socket,
                opponentId: user2_id,
                gameId,
            });
            connectedSockets.set(user2_id, {
                ...user2_socket,
                opponentSocket: user1_socket.socket,
                opponentId: user1_id,
                gameId,
            });

            user1_socket.socket.emit("game-start");
            user2_socket.socket.emit("game-start");
        }

        async function addUserToQueue() {
            try {
                await req.db.query(
                    `
            INSERT INTO queue (user_id, game_type)
            VALUES (:user_id, :game_type)
            ON DUPLICATE KEY UPDATE user_id = user_id;`,
                    {
                        user_id: user.userId,
                        game_type,
                    }
                );
                return { status: true };
            } catch (err) {
                console.error("Error - adding user to queue", err.message);
                return { status: "error", value: err.message };
            }
        }
    }
);

app.delete("/leave-queue", connectDatabase, verifyJwt, async (req, res) => {
    console.log("DELETE - leave queue")

    const { user } = req

    try {
        const [deleted] = await req.db.query(`
        DELETE FROM queue
        WHERE user_id = :userId
        `, {
            userId: user.userId
        })
        if (deleted.affectedRows === 0) {
            res.json(responseBuilder({msg:"user not in queue"},false))
        } else {
            res.json(responseBuilder({msg:"user removed from queue"}, false))
        }
    } catch (err) {
        console.error("Error - deleting user in queue")
        res.json(responseBuilder({msg:err.message}, true))
    }
})

// app.get("/user/:username",connectDatabase, verifyJwt, async (req, res) => {})

app.put(
    "/game-state",
    connectDatabase,
    verifyJwt,
    attachCurrentGame,
    async (req, res) => {
        console.log("PUT - game state");

        const { user, body, currentGame } = req;

        const userGameState = body.gameState;

        if (currentGame === null) {
            res.json(responseBuilder({ msg: "not currently in game" }, true));
            return;
        }

        const { id: gameId, user1_id, user2_id } = currentGame;
        const currentTurnCount = getTurnCount(currentGame.game_state);
        const correctTurn = currentGame.user1_id === user.userId ? 0 : 1;
        const userTurn = currentTurnCount % 2 === correctTurn;

        const defaultRes = (function () {
            const winner = checkWinner(currentGame.game_state);
            let gameStatus = "";

            if (winner !== null) {
                gameStatus =
                    winner === -1 ? "Draw" : winner === 0 ? "X Wins" : "O Wins";
            } else {
                gameStatus = userTurn ? "Your Turn" : "Opponents Turn";
            }
            return {
                gameState: currentGame.game_state,
                player: correctTurn,
                gameStatus,
                winner,
            };
        })();

        if (body.getUpdate) {
            if (currentGame.winner !== null)
                await updatePlayersCurrentGameToNull();
            res.json(
                responseBuilder({ msg: "Current State", ...defaultRes }, false)
            );
            return;
        }

        const correctTurnCount = getTurnCount(currentGame.game_state) + 1;
        const isCorrectTurnCount =
            correctTurnCount === getTurnCount(userGameState);
        const isValidTurn = checkCorrectTurn(
            currentGame.game_state,
            userGameState
        );
        if (!userTurn) {
            res.json(
                responseBuilder({ msg: "Not Your Turn", ...defaultRes }, true)
            );
            return;
        }
        if (!isCorrectTurnCount) {
            res.json(
                responseBuilder(
                    { msg: "Incorrect Amount Of Turns", ...defaultRes },
                    true
                )
            );
            return;
        }
        if (!isValidTurn) {
            res.json(
                responseBuilder({ msg: "Invalid Turn", ...defaultRes }, true)
            );
            return;
        }

        await updateGameState(userGameState);

        const oppSocket = connectedSockets.get(
            user.userId == currentGame.user1_id
                ? currentGame.user2_id
                : currentGame.user1_id
        );
        oppSocket.socket.emit("game-update");

        const finalRes = {
            ...defaultRes,
            gameState: userGameState,
            gameStatus: !userTurn ? "Your Turn" : "Opponents Turn",
        };

        const gameWinner = checkWinner(userGameState);
        finalRes.winner = gameWinner;

        if (gameWinner !== null) {
            const updatedGameWinner = await updateGameWinner(gameWinner);
            await updatePlayersCurrentGameToNull();
        }

        if (gameWinner === -1) {
            finalRes.gameStatus = "Draw";
        } else if (gameWinner === 0) {
            finalRes.gameStatus = "X Wins";
        } else if (gameWinner === 1) {
            finalRes.gameStatus = "0 Wins";
        }

        res.json(
            responseBuilder(
                { msg: "Turn Made", ...defaultRes, ...finalRes },
                false
            )
        );

        function checkWinner(gameState) {
            const lines = [
                [0, 1, 2],
                [3, 4, 5],
                [6, 7, 8],
                [0, 3, 6],
                [1, 4, 7],
                [2, 5, 8],
                [0, 4, 8],
                [2, 4, 6],
            ];
            for (let i = 0; i < lines.length; i++) {
                const [a, b, c] = lines[i];
                if (
                    gameState[a] != null &&
                    gameState[a] === gameState[b] &&
                    gameState[a] === gameState[c]
                ) {
                    return gameState[a];
                }
            }
            // check if draw
            if (gameState.every((a) => a != null)) {
                return -1;
            }
            return null;
        }

        function getTurnCount(gameState) {
            return gameState.filter((a) => a != null).length;
        }

        function checkCorrectTurn(oldGameState, newGameState) {
            let notMatched = 0;
            let moveMade = null;
            for (let i in oldGameState) {
                const move = newGameState[i];
                if (!(move == null || move == 0 || move == 1)) {
                    console.error("invalid turn type");
                    return false;
                }
                if (oldGameState[i] != move) {
                    notMatched++;
                    moveMade = move;
                }
            }

            if (notMatched > 1) {
                console.error("invalid changed turns", notMatched);
                return false;
            }
            if (moveMade !== currentTurnCount % 2) {
                console.error(
                    "invalid user turn",
                    moveMade,
                    correctTurnCount % 2
                );
                return false;
            }

            return true;
        }

        async function updateGameWinner(gameWinner) {
            try {
                await req.db.query(
                    `
            UPDATE games
            SET winner = :winner, end_time = NOW()
            WHERE id = :gameId AND winner IS NULL`,
                    {
                        winner:
                            gameWinner === -1
                                ? -1
                                : [user1_id, user2_id][gameWinner],
                        gameId,
                    }
                );
                return { status: "success" };
            } catch (err) {
                console.error("Error - updating game winner", err.message);
                return { status: "error", value: err.message };
            }
        }

        async function updatePlayersCurrentGameToNull() {
            try {
                await req.db.query(
                    `
            UPDATE users
            SET current_game = NULL
            WHERE id = :userId;
            `,
                    {
                        userId: user.userId,
                    }
                );
            } catch (err) {
                console.error(
                    "Error - setting current game to NULL",
                    err.message
                );
            }
        }

        async function updateGameState(gameState) {
            try {
                await req.db.query(
                    `
            UPDATE games
            SET game_state = :gameState
            WHERE id = :gameId;
            `,
                    {
                        gameState: JSON.stringify(gameState),
                        gameId,
                    }
                );

                return { status: "success" };
            } catch (err) {
                console.error("Error - updating game state", err.message);
                return { status: "error", value: err.message };
            }
        }
    }
);

app.get("/login", connectDatabase, (req, res) => {
    res.sendFile(path.join(__dirname, "dist", "index.html"));
});
app.get("*", connectDatabase, (req, res) => {
    res.sendFile(path.join(__dirname, "dist", "index.html"));
});

// start the Express server
server.listen(port, () => {
    console.log(`Server started at http://localhost:${port}`);
});
