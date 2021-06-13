from enum import unique
from flask import Flask
from flask_restful import Resource, Api, reqparse, request, inputs
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method
from flask_restful import fields, marshal_with, marshal
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
from flask_jwt_extended import JWTManager
from flask_cors import CORS
import flask_sqlalchemy

from passlib.hash import pbkdf2_sha256 as sha256
import datetime
import subprocess
import os
import sys
from random import randrange



app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tictactogether.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
app.config['BUNDLE_ERRORS'] = False
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'supersecret'
app.config['SECURITY_PASSWORD_SALT'] = 'supersecret'

jwt = JWTManager(app) #http://codeburst.io/jwt-authorization-in-flask-c63c1acf4
api = Api(app)
db = SQLAlchemy(app)
db.create_all()

badwords = []
with open('./badwords') as f:
    badwords = [line.rstrip() for line in f]

class Player(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique = True, nullable = False)
    password = db.Column(db.String(256), nullable = False)
    wins = db.Column(db.Integer, default=0)
    losses = db.Column(db.Integer, default=0)
    is_x = db.Column(db.Boolean)

    game_moves = db.relationship('GameMove', backref='player', lazy=False)


    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
    def delete_object(self):
        db.session.delete(self)
        db.session.commit()
        
    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)

    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)

    def __repr__(self):
        return '<Player %r>' % self.player_name


class GameMove(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'))
    player_id = db.Column(db.Integer, db.ForeignKey('player.id'))
    move_order = db.Column(db.Integer)
    x_pos = db.Column(db.Integer)
    y_pos = db.Column(db.Integer)

    @hybrid_property
    def player_name(self):
        tmp = Player.query.filter_by(id=self.player_id).first()
        return tmp.username

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_object(self):
        db.session.delete(self)
        db.session.commit()

class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    game_moves = db.relationship('GameMove', backref='game', lazy=False)
    locked = db.Column(db.Boolean)
    finished = db.Column(db.Boolean)
    is_winner_x = db.Column(db.Boolean)
    
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_object(self):
        db.session.delete(self)
        db.session.commit()

        
    @classmethod
    def find_new_game(cls, player_id):
        tmp_objs = cls.query.filter_by(finished=False, locked=False).all()
        for tmp_obj in tmp_objs:
            player_exists = False
            for move in tmp_obj.game_moves:
                if move.player_id == player_id:
                    player_exists = True
            if not player_exists:
                return tmp_obj
        return False


login_parser = reqparse.RequestParser()
login_parser.add_argument('username', location='json', help = 'This field cannot be blank', required = True)
login_parser.add_argument('password', type=str, help = 'This field cannot be blank', required = True)


class Login(Resource):
    def post(self):
        print("Login method called", file=sys.stderr)
        print(request.values)
        args = login_parser.parse_args()
        player_obj = Player.query.filter_by(username=args['username']).first()
        if not player_obj:
            if args['username'] not in badwords:
                print("New User Registration", file=sys.stderr)
                player_obj = Player(
                    username = args['username'],
                    password = Player.generate_hash(args['password'])
                )
                try:
                    print("Attempting to save user", file=sys.stderr)
                    player_obj.save_to_db()
                    expires = datetime.timedelta(hours=24)
                    access_token = create_access_token(identity = args['username'], expires_delta=expires) #Expire it fast for testing
                    refresh_token = create_refresh_token(identity = args['username'])
                except:
                    return { 'message' : 'Registration Failed' }
                return { 
                    'message' : 'Logged in as {}'.format(player_obj.username),
                    'access_token' : access_token,
                    'refresh_token' : refresh_token
                }
            else:
                return { 'message' : "Naughty username detected" }
        if Player.verify_hash(args['password'], player_obj.password):
            print("Login Existing User")
            expires = datetime.timedelta(hours=24)
            access_token = create_access_token(identity = args['username'], expires_delta=expires)
            refresh_token = create_refresh_token(identity = args['username'])
            return { 
                'message' : 'Logged in as {}'.format(player_obj.username),
                'access_token' : access_token,
                'refresh_token' : refresh_token
            }
        else:
            return { 'message' : 'Login Failed' }


player_stats = {
    'wins' : fields.Integer,
    'losses' : fields.Integer,
    'active_games' : fields.Integer,
    'total_games' : fields.Integer,
    'finished_games' : fields.Integer,
    'x_games' : fields.Integer,
    'o_games' : fields.Integer,
    'total_players' : fields.Integer
}

class GetStats(Resource):
    @jwt_required
    def get(self):
        username = get_jwt_identity()
        player_obj = Player.query.filter_by(username=username).first()
        act_games = Game.query.filter_by(finished=False).all()
        fin_games = Game.query.filter_by(finished=True).all()
        total_games = Game.query.all()

        x_games = Game.query.filter_by(finished=True, is_winner_x=True).all()
        o_games = Game.query.filter_by(finished=True, is_winner_x=False).all()

        total_players = Player.query.all()

        response = {
            'wins' : player_obj.wins,
            'losses' : player_obj.losses,
            'active_games' : len(act_games),
            'total_games' : len(total_games),
            'finished_games' : len(fin_games),
            'x_games' : len(x_games),
            'o_games' : len(o_games),
            'total_players' : len(total_players),
        }
        return marshal(response, player_stats)


class AuthCheck(Resource):
    @jwt_required
    def get(self):
        return { 'message' : 'success' }

game_move_fields = {
    'id' : fields.Integer,
    'game_id' : fields.Integer,
    'player_id' : fields.Integer,
    'player_name' : fields.String,
    'move_order' : fields.Integer,
    'is_x' : fields.Boolean,
    'x_pos' : fields.Integer,
    'y_pos' : fields.Integer
}

game_fields = {
    'id': fields.Integer,
    'locked': fields.Boolean,
    'finished': fields.Boolean,
    'game_moves': fields.List(fields.Nested(game_move_fields)),
}

class GetInstance(Resource):
    @jwt_required
    def get(self):
        username = get_jwt_identity()
        player_obj = Player.query.filter_by(username=username).first()
        game_obj = Game.find_new_game(player_obj.id)
        if not game_obj:
            game_obj = Game.query.filter_by(finished=False, locked=False).first()

        if not game_obj:
            game_obj = Game(
                locked = True,
                finished = False,
            )
            game_obj.save_to_db()
            return marshal(game_obj, game_fields)
        else:
            game_obj.locked = True
            game_obj.save_to_db()
            return marshal(game_obj, game_fields)

move_parser = reqparse.RequestParser()
move_parser.add_argument('x', help = 'This field cannot be blank', required = True)
move_parser.add_argument('y', help = 'This field cannot be blank', required = True)
move_parser.add_argument('game_id',help = 'This field cannot be blank', required = True)
move_parser.add_argument('is_x', type=inputs.boolean, help = 'This field cannot be blank', required = True)
class MakeMove(Resource):
    @jwt_required
    def post(self):
        args = move_parser.parse_args()
        game_obj = Game.query.filter_by(id=args['game_id']).first()
        invalid_move = False
        for move in game_obj.game_moves:
            if move.x_pos == args['x']:
                if move.y_pos == args['y']:
                    invalid_move = True
        if not invalid_move:

            map_arr = [[0, 0, 0], [0, 0, 0], [0, 0, 0]]

            username = get_jwt_identity()
            player_obj = Player.query.filter_by(username=username).first()
            current_move = 0
            for move in game_obj.game_moves:
                if move.move_order >= current_move:
                    current_move = move.move_order + 1
                    if move.is_x:
                        map_arr[move.y_pos][move.x_pos] = 2
                    else:
                        map_arr[move.y_pos][move.x_pos] = 1

            move_obj = GameMove(
                x_pos = args['x'],
                y_pos = args['y'],
                game_id = args['game_id'],
                player_id = player_obj.id,
                is_x = args['is_x'],
                move_order = current_move
            )
            move_obj.save_to_db()
            game_obj.locked = False
            game_obj.save_to_db()
        
            if args['is_x']:
                map_arr[int(args['y'])][int(args['x'])] = 2
            else:
                map_arr[int(args['y'])][int(args['x'])] = 1
            print(map_arr)


            victory = False
            victor = 0
            for y in range(0, 3):
                all_1 = True
                all_2 = True
                for x in range(0, 3):
                    if map_arr[y][x] == 1:
                        all_2 = False
                    if map_arr[y][x] == 2:
                        all_1 = False
                    if map_arr[y][x] == 0:
                        all_1 = False
                        all_2 = False
                if all_1 or all_2:
                    victory = True
                    if all_1:
                        victor = 1
                    else:
                        victor = 2
            for x in range(0, 3):
                all_1 = True
                all_2 = True
                for y in range(0, 3):
                    if map_arr[y][x] == 1:
                        all_2 = False
                    if map_arr[y][x] == 2:
                        all_1 = False
                    if map_arr[y][x] == 0:
                        all_1 = False
                        all_2 = False
                if all_1 or all_2:
                    victory = True
                    if all_1:
                        victor = 1
                    else:
                        victor = 2

            if victory:
                game_obj.finished = True
                if victor == 2:
                    game_obj.is_winner_x = True
                    done_players = []
                    for move in game_obj.game_modes:
                        if move.player_id not in done_players:
                            if move.is_x:
                                tmp_obj = Player.query.filter_by(id=move.player_id).first()
                                tmp_obj.wins = tmp_obj.wins + 1
                                tmp_obj.save_to_db()
                                done_players.append(move.player_id)
                            else:
                                tmp_obj = Player.query.filter_by(id=move.player_id).first()
                                tmp_obj.losses = tmp_obj.losses + 1
                                tmp_obj.save_to_db()
                                done_players.append(move.player_id)

                else:
                    game_obj.is_winner_x = False
                    done_players = []
                    for move in game_obj.game_moves:
                        if move.player_id not in done_players:
                            if move.is_x:
                                tmp_obj = Player.query.filter_by(id=move.player_id).first()
                                tmp_obj.losses = tmp_obj.losses + 1
                                tmp_obj.save_to_db()
                                done_players.append(move.player_id)
                            else:
                                tmp_obj = Player.query.filter_by(id=move.player_id).first()
                                tmp_obj.wins = tmp_obj.wins + 1
                                tmp_obj.save_to_db()
                                done_players.append(move.player_id)

                game_obj.save_to_db()
            

	
            return { 'message' : 'Move Completed' }

#Setup the db if not done already
db.create_all()


api.add_resource(Login, '/login')
api.add_resource(GetStats, '/getstats')
api.add_resource(AuthCheck, '/authcheck')
api.add_resource(GetInstance, '/getinstance')
api.add_resource(MakeMove, '/makemove')


if __name__ == '__main__':
    app.run(debug=True,  port=8000)
