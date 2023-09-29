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
        // console.log("token",token)
        const payload = jwt.verify(token, process.env.JWT_KEY);
        return { data: payload };
    } catch (err) {
        return { error: err.message };
    }
};

app.use(cors(corsOptions));

app.use(bodyParser.json());

// app.use(cookieParser());

// io.on("connect_error", (err) => {
//   console.log(`connect_error due to ${err.message}`);
// });

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
    // const room = crypto.randomUUID();
    socket.userId = payload.data.userId;
    connectedSockets.set(payload.data.userId, {
        socket,
        // room,
        opponentSocket: null,
        opponentId: null,
    });

    // socket.join(room);
    // console.log("con",io.sockets.adapter.rooms.get("test_room"));
    socket.on("disconnect", () => {
        // console.log("dis",io.sockets.adapter.rooms.get("test_room"));
        console.log("user disconnected");
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
        console.log(err);
        if (req.db) req.db.release();
        throw err;
    }
};

// app.use();

// app.get("/", async function(req,res) {
//     res.sendFile(path.join(__dirname, "dist", "index.html"))
// })

app.post("/register", connectDatabase, async function (req, res) {
    try {
        let encodedUser;
        let resError;

        // Hashes the password and inserts the info into the `user` table
        await bcrypt.hash(req.body.password, 10).then(async (hash) => {
            try {
                // console.log(await req.db.query("Select * from users"))
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
                // res.json({"user_jwt":encodedUser})
                console.log(encodedUser);
            } catch (error) {
                resError = error;
                console.log("error", error);
            }
        });

        // res.cookie('user_jwt', `${encodedUser}`, {
        //   httpOnly: true
        // });

        if (resError) {
            if (resError.code === "ER_DUP_ENTRY")
                res.json(
                    responseBuilder({ msg: "Username Already Exists" }, true)
                );
        } else res.json(responseBuilder({ jwt: encodedUser }, false));
    } catch (err) {
        console.log("err", err);
        console.log(err);
        res.json(responseBuilder({ msg: "Error Occurred Try Again" }, true));
    }
});

app.post("/authenticate", connectDatabase, async function (req, res) {
    try {
        const { username, password } = req.body;
        console.log(username, password);
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

            res.json(responseBuilder({ jwt: encodedUser }, false));
        } else {
            res.json(responseBuilder({ msg: "Password not found" }, true));
        }
    } catch (err) {
        console.log("Error in /authenticate", err);
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
        // console.log(payload);
        req.user = payload;
    } catch (err) {
        console.log(err);
        if (
            err.message &&
            (err.message.toUpperCase() === "INVALID TOKEN" ||
                err.message.toUpperCase() === "JWT EXPIRED")
        ) {
            // req.status = err.status || 500;
            req.body = err.message;
            // req.app.emit("jwt-error", err, req);
            // res.json("Error")
            await next();
        } else {
            // next(err.status )
            next(err.status || 500, err.message);
        }
    }

    await next();
};
// app.use();
// app.use(verifyJwt)

// app.use((err,req,res,next)=>{
//     console.error(err.stack)
//     res.json("error")
// })

app.get("/history", connectDatabase, verifyJwt, async (req, res) => {
    console.log("queue GET");
    try {
        const { user, body, params } = req;
        // console.log(params,query,user)

        const [history] = await req.db.query(
            `
            SELECT * FROM games
            WHERE (
                user1_id = :userId
                OR user2_id = :userId
            )
            AND winner IS NULL`,
            { userId: user.userId }
        );

        res.json(responseBuilder(history, false));
    } catch (err) {
        res.json(responseBuilder(null, true));
    }
});

app.post("/join-queue", connectDatabase, verifyJwt, async (req, res) => {
    console.log("join-queue");
    const { user } = req;
    const game_type = 0;
    
    const userInGame = await checkIfUserIsInGame();
    
    if (userInGame.status === "success") {
        res.json(responseBuilder({code: 1, msg: "already in game" }, true));
        return;
    } else if (userInGame.status === "error") {
        res.json(responseBuilder({ code: 0, msg: userInGame.value }, true));
        return;
    }
    
    const userInQueue = await addUserToQueue();
    console.log("check",user.userId)
    
    if (userInQueue.status === "error") {
        res.json(responseBuilder({code: 2, msg: userInQueue.value }, true));
        return;
    }

    const opponentInQueue = await getFirstOpponentFromQueue();

    if (opponentInQueue.status === "error") {
        res.json(responseBuilder({code:0, msg: opponentInQueue.value }, true));
        return;
    } else if (opponentInQueue.status === "failed") {
        res.json(responseBuilder({code:0, msg: "Waiting for Opponent..." }, false)); // no opponent
        return;
    }

    const opponent = opponentInQueue.value;

    const game = await createGame(
        req.db,
        [user.userId, opponent.user_id],
        game_type
    );
    // console.log("user ids",user.userId, opponent.user_id)
    addPlayerSocketsToMap(user.userId, opponent.user_id);

    res.json(responseBuilder({code:3, msg: "Game Starting...", status: true }, false));

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
            console.log("Error - match err: ", err.message);
            return { status: "error", value: err.message };
            // res.json(responseBuilder({ msg: err.message, status: "error" }, true));
        }
    }

    async function createGame(db, playerIds, gameType) {
        const rand = Math.random() >= 0.5 ? [0, 1] : [1, 0];
        const player1 = playerIds[rand[0]];
        const player2 = playerIds[rand[1]];

        // console.log(player1,player2,rand)

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

            return { status: "success", value: game.insertId };
            // return { msg: "success", gameId: game.insertId, error: false };
        } catch (err) {
            console.error("Error - create game", err.message);
            return { status: "error", value: err.message };
            // return { msg: err.message, error: true };
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
                console.log(
                    `users ${player1} and ${player2} removed from queue`
                );
            } catch (err) {
                console.error(
                    "Error - remove players from queue: ",
                    err.message
                );
            }
        }
    }

    function addPlayerSocketsToMap(user_id, opponent_id) {
        const userSocket = connectedSockets.get(user_id);
        const opponentSocket = connectedSockets.get(opponent_id);

        console.log({userSocket, opponentSocket})

        if (!userSocket || !opponentSocket) return;

        connectedSockets.set(user_id, {
            ...userSocket,
            opponentSocket: opponentSocket.socket,
            opponentId: opponent_id,
            gameId: game.gameId,
        });
        connectedSockets.set(opponent_id, {
            ...opponentSocket,
            opponentSocket: userSocket.socket,
            opponentId: user_id,
            gameId: game.gameId,
        });

        userSocket.socket.emit("game-start");
        opponentSocket.socket.emit("game-start");
        console.log("pinged", user_id, "and", opponent_id, "to start game")
    }

    async function checkIfUserIsInGame() {
        try {
            const [gamesUserIsIn] = await req.db.query(
                `
                SELECT * FROM games
                WHERE (
                    user1_id = :user_id OR user2_id = :user_id
                )
                AND winner IS NULL`,
                {
                    user_id: user.userId,
                }
            );
            if (gamesUserIsIn.length) return { status: "success" };
        } catch (err) {
            console.error("Error - in game: ", err.message);
            return { status: "error", value: err.message };
        }
        return { status: true };
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
            // if (err.code === "ER_DUP_ENTRY") userAlreadyInQueue = true;
            // else

            return { status: "error", value: err.message };
        }
    }
    //res.json(responseBuilder({msg:"Waiting For Opponent..."},false))
});

app.put("/game-state", connectDatabase, verifyJwt, async (req, res) => {
    console.log("PUT - game state");

    const { user, body } = req;

    const userGameState = body.gameState;
    console.log(user.userId,userGameState);
    // const test = connectedSockets.get(user.userId)
    // console.log(user.userId);
    // let game
    const gotGame = await getGameData();
    if (gotGame.status === "error") {
        res.redirect("/");
        // res.json(responseBuilder({ msg: gotGame.value }, true));
        return;
    }
    if (gotGame.status === "failed") {
        res.redirect("/");
        return;
    }

    const game = gotGame.value;
    const { id: gameId, user1_id, user2_id } = game;
    const currentTurnCount = getTurnCount(game.game_state);
    const correctTurn = game.user1_id === user.userId ? 0 : 1;
    const userTurn = currentTurnCount % 2 === correctTurn;

    // const 

    const defaultRes = function(){
        // console.log(game.game_state)
        const winner = checkWinner(game.game_state)
        let gameStatus = ""

        if (winner !== null) {
            gameStatus = winner === -1 ? "Draw" : winner === 0 ? "X Wins" : "O Wins"
        } else {
            gameStatus = userTurn ? "Your Turn" : "Opponents Turn"
        }
        return {
            gameState: game.game_state,
            player: correctTurn,
            gameStatus,//: checkWinner(game.gameState) != null ? userTurn ? "Your Turn" : "Opponents Turn"
            winner
        }
    }();

    if (body.getUpdate) {
        res.json(
            responseBuilder({ msg: "Current State", ...defaultRes }, false)
        );
        return;
    }

    // const tooManyEntries == game
    const correctTurnCount = getTurnCount(game.game_state) + 1;
    const isCorrectTurnCount = correctTurnCount === getTurnCount(userGameState);
    const isValidTurn = checkCorrectTurn(game.game_state, userGameState);
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
        res.json(responseBuilder({ msg: "Invalid Turn", ...defaultRes }, true));
        return;
    }

    await updateGameState(userGameState);


    const oppSocket = connectedSockets.get(
        user.userId == game.user1_id ? game.user2_id : game.user1_id
    );
    oppSocket.socket.emit("game-update");

    const finalRes = {
        ...defaultRes,
        gameState: userGameState,
        gameStatus: !userTurn ? "Your Turn" : "Opponents Turn",
    };

    const gameWinner = checkWinner(userGameState);
    finalRes.winner = gameWinner
    
    if (gameWinner !== null) {
        // console.log({gameWinner})
        const updatedGameWinner = await updateGameWinner(gameWinner)
        console.log({updatedGameWinner})
    }

    if (gameWinner === -1) {
        finalRes.gameStatus = "Draw";
    } else if (gameWinner === 0) {
        finalRes.gameStatus = "X Wins";
    } else if (gameWinner === 1) {
        finalRes.gameStatus = "0 Wins";
    }

    res.json(
        responseBuilder({ msg: "Turn Made", ...defaultRes, ...finalRes }, false)
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
                console.log("invalid turn type");
                return false;
            }
            if (oldGameState[i] != move) {
                notMatched++;
                moveMade = move;
            }
        }

        if (notMatched > 1) {
            console.log("invalid changed turns", notMatched);
            return false;
        }
        if (moveMade !== currentTurnCount % 2) {
            console.log("invalid user turn", moveMade, correctTurnCount % 2);
            return false;
        }

        return true;
    }

    async function updateGameWinner(gameWinner) {
        try {
            await req.db.query(`
            UPDATE games
            SET winner = :winner, end_time = NOW()
            WHERE id = :gameId AND winner IS NULL`, {
                winner: gameWinner === -1 ? -1 : [user1_id, user2_id][gameWinner],
                gameId
            })
            return {status: "success"}
        } catch (err) {
            console.error("Error - updating game winner", err.message)
            return {status: "error", value: err.message}
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
            // console.log({ updated });
            return { status: "success" };
        } catch (err) {
            console.error("Error - updating game state", err.message);
            return { status: "error", value: err.message };
        }
    }

    async function getGameData(gameId) {
        // gameId = connectedSockets.get(user.userId).game;
        try {
            const [[gameData]] = await req.db.query(
                `
            SELECT * FROM games
            WHERE (
                user1_id = :userId OR user2_id = :userId
                )
            AND winner IS NULL
            LIMIT 1;
            `,
                {
                    userId: user.userId,
                }
            );
            if (!gameData) return { status: "failed", value: "No Games Found" };
            return { status: "success,", value: gameData };
        } catch (err) {
            console.error("Error - getting game from database", err.message);
            return { status: "error", value: err.message };
        }
    }
});

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
