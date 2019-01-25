package ttl.intern.project.forumAuthServer;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.vertx.config.ConfigRetriever;
import io.vertx.config.ConfigRetrieverOptions;
import io.vertx.config.ConfigStoreOptions;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.NetServer;
import io.vertx.core.net.NetServerOptions;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
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
		
		// TODO read from conf file
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

	public enum ErrorCodes {
		NO_ACTION_SPECIFIED, BAD_ACTION, DATA_ERROR, DB_ERROR
	}

	public void onMessage(Message<JsonObject> message) {
		if (!message.headers().contains("action")) {
			LOGGER.error("No action header specified for message with headers {} and body {}", message.headers(),
					message.body().encodePrettily());
			message.fail(ErrorCodes.NO_ACTION_SPECIFIED.ordinal(), "No action header specified");
			return;
		}

		String action = message.headers().get("action");

		// todo: class call
		switch (action) {
		case "login":
			LOGGER.info("action: authenticate User");
			login(message);
			break;
		case "is-authorized":
			isAuthorized(message);
			break;
		case "signup":
			createUser(message);
			break;
		case "update-user-password":
			updateUserPassword(message);
			break;
		case "update-user-roles":
			updateUserRole(message);
			break;
		case "update-user-permissions":
			updateUserPermisssions(message);
			break;
		default:
			message.fail(ErrorCodes.BAD_ACTION.ordinal(), "Bad action: " + action);
		}
	}

	private void updateUserRole(Message<JsonObject> message) {
		authenticateJWT(new JsonObject().put("jwt", message.body().getString("jwt")), res -> {
			if (res.succeeded()) {
				MongoUser user = res.result();

				user.isAuthorized("admin", response -> {
					if (response.succeeded()) {
						List<String> roles = new ArrayList<>();
						roles.add(message.body().getString("role"));

						mongoProvider.insertUser(message.body().getString("username"),
								message.body().getString("password"), roles, new ArrayList<String>(), handle -> {
									if (handle.succeeded()) {
										message.reply("create user successful");
									} else {
										message.fail(ErrorCodes.DB_ERROR.ordinal(), handle.cause().toString());
									}

								});
					} else {
						message.fail(ErrorCodes.DATA_ERROR.ordinal(), response.cause().toString());
					}
				});
			} else {
				message.fail(ErrorCodes.DATA_ERROR.ordinal(), res.cause().toString());
			}
		});
		
	}

	private void updateUserPermisssions(Message<JsonObject> message) {

	}

	private void updateUserPassword(Message<JsonObject> message) {
		authenticateJWT(new JsonObject().put("jwt", message.body().getString("jwt")), userResult -> {
			if (userResult.succeeded()) {
				MongoUser user = userResult.result();
				
				String password = mongoProvider.getHashStrategy().computeHash(message.body().getString("password"), user);
				
				user.principal().remove("password");
				user.principal().put("password", password);
				
				JsonObject query = new JsonObject().put("username", user.principal().getString("username"));
				JsonObject replace = user.principal();
				
				mongoClient.findOneAndReplace("user", query, replace, res -> {
					if (res.succeeded()) {
						message.reply("update user password successful");
					} else {
						System.out.println(res.cause());
						message.fail(ErrorCodes.DB_ERROR.ordinal(), res.cause().toString());
					}
				});
				
				System.out.println("password: " + password);
			} else {
				message.fail(ErrorCodes.DB_ERROR.ordinal(), userResult.cause().toString());
			}
		});

	}

	private void createUser(Message<JsonObject> message) {
		authenticateJWT(new JsonObject().put("jwt", message.body().getString("jwt")), res -> {
			if (res.succeeded()) {
				MongoUser user = res.result();

				user.isAuthorized("admin", response -> {
					if (response.succeeded()) {
						List<String> roles = new ArrayList<>();
						roles.add(message.body().getString("role"));

						mongoProvider.insertUser(message.body().getString("username"),
								message.body().getString("password"), roles, new ArrayList<String>(), handle -> {
									if (handle.succeeded()) {
										message.reply("create user successful");
									} else {
										message.fail(ErrorCodes.DB_ERROR.ordinal(), handle.cause().toString());
									}

								});
					} else {
						message.fail(ErrorCodes.DATA_ERROR.ordinal(), response.cause().toString());
					}
				});
			} else {
				message.fail(ErrorCodes.DATA_ERROR.ordinal(), res.cause().toString());
			}
		});
		
		

	}

	private void isAuthorized(Message<JsonObject> message) {
		// TODO Auto-generated method stub

	}

	private void login(Message<JsonObject> message) {
		authenticateLogin(message.body(), res -> {
			if (res.succeeded()) {
				MongoUser user = res.result();
				message.reply(generateToken(user.principal().getString("username")));
			} else {

				message.fail(ErrorCodes.DATA_ERROR.ordinal(), res.cause().getMessage());
			}
		});
	}

	private String generateToken(String username) {
		String token = jwtProvider.generateToken(new JsonObject().put("username", username));

		return token;
	}

	private void authenticateLogin(JsonObject authInfo, Handler<AsyncResult<MongoUser>> handler) {
		mongoProvider.authenticate(authInfo, res -> {
			if (res.succeeded()) {
				MongoUser user = new MongoUser(res.result().principal(), mongoProvider);
				handler.handle(Future.succeededFuture(user));
			} else {
				handler.handle(Future.failedFuture(res.cause()));
			}
		});
	}

	private void authenticateJWT(JsonObject authInfo, Handler<AsyncResult<MongoUser>> handler) {
		jwtProvider.authenticate(authInfo, res -> {
			User user = res.result();
			JsonObject query = new JsonObject().put(mongoProvider.getUsernameField(),
					user.principal().getString("username"));
			mongoClient.find("user", query, response -> {
				if (response.succeeded()) {
					MongoUser mongoUser = new MongoUser(response.result().get(0), mongoProvider);
					handler.handle(Future.succeededFuture(mongoUser));
				} else {
					handler.handle(Future.failedFuture(response.cause()));
				}
			});
		});
	}

}
