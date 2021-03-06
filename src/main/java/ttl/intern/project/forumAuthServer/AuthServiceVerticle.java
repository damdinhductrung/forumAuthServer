package ttl.intern.project.forumAuthServer;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.auth.mongo.AuthenticationException;
import io.vertx.ext.auth.mongo.MongoAuth;
import io.vertx.ext.auth.mongo.impl.MongoUser;
import io.vertx.ext.mongo.MongoClient;

public class AuthServiceVerticle extends AbstractVerticle {
	private Logger LOGGER = LoggerFactory.getLogger(AuthServiceVerticle.class);

	private MongoClient mongoClient;
	private MongoAuth mongoProvider;
	private JWTAuth jwtProvider;

	@Override
	public void start(Future<Void> future) {

		JsonObject mongoClientConf = new JsonObject().put("connection_string", config().getString("connection-string"));

		try {
			PubSecKeyOptions pubSecKeyOptions = new PubSecKeyOptions(config().getJsonObject("pubSecKeys"));

			mongoClient = MongoClient.createShared(vertx, mongoClientConf);
			mongoProvider = MongoAuth.create(mongoClient, new JsonObject());
			jwtProvider = JWTAuth.create(vertx, new JWTAuthOptions().addPubSecKey(pubSecKeyOptions));

			vertx.eventBus().consumer(config().getString("eventBus.address"), this::onMessage);

			LOGGER.info("successfull eventbus");

			future.complete();
		} catch (Exception ex) {
			future.fail(ex.getCause());
		}

	}

	public void onMessage(Message<JsonObject> message) {
		LOGGER.info("Incomming Message");
		if (!message.headers().contains("action")) {
			LOGGER.error("No action header specified for message with headers {} and body {}", message.headers(),
					message.body().encodePrettily());
			message.fail(EBCode.NO_ACTION_SPECIFIED.ordinal(), "No action header specified");
			return;
		}

		String action = message.headers().get("action");

		// TODO class call
		switch (action) {
		case Consts.EB_ACTION_LOGIN:
			LOGGER.info("action: " + Consts.EB_ACTION_LOGIN);
			login(message);
			break;
		case Consts.EB_ACTION_SIGNUP:
			LOGGER.info("action: " + Consts.EB_ACTION_SIGNUP);
			signup(message);
			break;
//		case Consts.EB_ACTION_UPDATE_USER_PASSWORD:
//			LOGGER.info("action: " + Consts.EB_ACTION_UPDATE_USER_PASSWORD);
//			updateUserPassword(message);
//			break;
		case Consts.EB_ACTION_JWT_AUTHORIZATION:
			LOGGER.info("action: " + Consts.EB_ACTION_JWT_AUTHORIZATION);
			jwtAuthorization(message);
			break;
		default:
			LOGGER.info("Bad action: " + action);
			message.fail(EBCode.BAD_ACTION.ordinal(), "Bad action: " + action);
		}
	}

//	private void updateUserRole(Message<JsonObject> message) {
//		authenticateJWT(new JsonObject().put("jwt", message.body().getString("jwt")), res -> {
//			if (res.succeeded()) {
//				MongoUser user = res.result();
//
//				user.isAuthorized("admin", response -> {
//					if (response.succeeded()) {
//						List<String> roles = new ArrayList<>();
//						roles.add(message.body().getString("role"));
//
//						mongoProvider.insertUser(message.body().getString("username"),
//								message.body().getString("password"), roles, new ArrayList<String>(), handle -> {
//									if (handle.succeeded()) {
//										message.reply("create user successful");
//									} else {
//										message.fail(ErrorCodes.DB_ERROR.ordinal(), handle.cause().toString());
//									}
//
//								});
//					} else {
//						message.fail(ErrorCodes.DATA_ERROR.ordinal(), response.cause().toString());
//					}
//				});
//			} else {
//				message.fail(ErrorCodes.DATA_ERROR.ordinal(), res.cause().toString());
//			}
//		});
//
//	}

//	private void updateUserPassword(Message<JsonObject> message) {
//		authenticateJWT(new JsonObject().put("jwt", message.body().getString("jwt")), userResult -> {
//			if (userResult.succeeded()) {
//				MongoUser user = userResult.result();
//
//				if (mongoProvider.getHashStrategy().computeHash(message.body().getString("oldPassword"), user)
//						.equals(user.principal().getString("password"))) {
//
//					String password = mongoProvider.getHashStrategy()
//							.computeHash(message.body().getString("newPassword"), user);
//
//					user.principal().remove("password");
//					user.principal().put("password", password);
//
//					JsonObject query = new JsonObject().put("username", user.principal().getString("username"));
//					JsonObject replace = user.principal();
//
//					mongoClient.findOneAndReplace("user", query, replace, res -> {
//						if (res.succeeded()) {
//							message.reply(EBCode.SUCCESSFUL);
//						} else {
//							LOGGER.error(res.cause().toString());
//							message.fail(EBCode.ERROR_DATABASE.ordinal(), res.cause().toString());
//						}
//					});
//
//				} else {
//					message.fail(EBCode.ERROR_UPDATE_PASSWORD_INVALID_OLDPASS.ordinal(), "Wrong old password");
//				}
//			} else {
//				message.fail(EBCode.ERROR_DATABASE.ordinal(), userResult.cause().toString());
//			}
//		});
//
//	}

	private void signup(Message<JsonObject> message) {
		List<String> roles = new ArrayList<>();
		roles.add("member");

		mongoClient.find("user", new JsonObject().put("username", message.body().getString("username")), res -> {
			if (res.succeeded()) {
				if (res.result().isEmpty()) {
					mongoProvider.insertUser(message.body().getString("username"), message.body().getString("password"),
							roles, new ArrayList<String>(), handle -> {
								if (handle.succeeded()) {
									message.reply(EBCode.SUCCESSFUL);
								} else {
									message.fail(EBCode.ERROR_DATABASE.ordinal(), handle.cause().toString());
								}

							});
				} else {
					message.fail(EBCode.ERROR_SIGNUP_USERNAME_EXITED.ordinal(), "Username has been already taken");
				}
			} else {
				message.fail(EBCode.ERROR_DATABASE.ordinal(), res.cause().toString());
			}
		});

	}

	private void login(Message<JsonObject> message) {
		authenticateUser(message.body(), res -> {
			if (res.succeeded()) {
				MongoUser user = res.result();
				String jwt = generateJWT(user.principal().getString("username"),
						user.principal().getJsonArray("roles").getString(0));
				message.reply(jwt);
			} else {
				if (res.cause().getClass().equals(AuthenticationException.class)) {
					message.fail(EBCode.ERROR_LOGIN_INVALID.ordinal(), "Invalid usernam or password");
				} else {
					message.fail(EBCode.ERROR_DATABASE.ordinal(), "");
				}
			}
		});
	}
	
	private void jwtAuthorization(Message<JsonObject> message) {
		authenticateJWT(message.body(), res -> {
			if (res.succeeded()) {
				message.reply(res.result());
			} else {
				res.cause().printStackTrace();
				message.fail(EBCode.ERROR_INVALID_TOKEN.ordinal(), "Invalid token");
			}
		});
	}

	private String generateJWT(String username, String role) {
		String token = jwtProvider.generateToken(new JsonObject().put("username", username).put("role", role));
		return token;
	}

	private void authenticateUser(JsonObject authInfo, Handler<AsyncResult<MongoUser>> handler) {
		mongoProvider.authenticate(authInfo, res -> {
			if (res.succeeded()) {
				MongoUser user = new MongoUser(res.result().principal(), mongoProvider);
				handler.handle(Future.succeededFuture(user));
			} else {
				handler.handle(Future.failedFuture(res.cause()));
			}
		});
	}

	private void authenticateJWT(JsonObject authInfo, Handler<AsyncResult<JsonObject>> handler) {
		jwtProvider.authenticate(authInfo, res -> {
			if (res.succeeded()) {
				User user = res.result();
				handler.handle(Future.succeededFuture(user.principal()));
//				JsonObject query = new JsonObject().put(mongoProvider.getUsernameField(),
//						user.principal().getString("username"));
//				mongoClient.find("user", query, response -> {
//					if (response.succeeded()) {
//						MongoUser mongoUser = new MongoUser(response.result().get(0), mongoProvider);
//						handler.handle(Future.succeededFuture(mongoUser));
//					} else {
//						handler.handle(Future.failedFuture(response.cause()));
//					}
//				});
			} else {
				handler.handle(Future.failedFuture(res.cause()));
			}
			
		});
	}

}
