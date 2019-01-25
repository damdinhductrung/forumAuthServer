package ttl.intern.project.forumAuthServer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.vertx.config.ConfigRetriever;
import io.vertx.config.ConfigRetrieverOptions;
import io.vertx.config.ConfigStoreOptions;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.core.spi.cluster.ClusterManager;
import io.vertx.spi.cluster.hazelcast.HazelcastClusterManager;

public class MainVerticle extends AbstractVerticle {

	private static Logger LOGGER = LoggerFactory.getLogger(MainVerticle.class);

	public static void main(String[] args) {

		Vertx vertxTmp = Vertx.vertx();

		ConfigRetriever retriever = ConfigRetriever.create(vertxTmp,
				new ConfigRetrieverOptions().addStore(new ConfigStoreOptions().setType("file")
						.setConfig(new JsonObject().put("path", "application-conf.json"))));

		retriever.getConfig(json -> {
			JsonObject conf = json.result();
			vertxTmp.close();

			ClusterManager mgr = new HazelcastClusterManager();
			VertxOptions options = new VertxOptions().setClusterManager(mgr).setClusterHost(conf.getJsonObject("cluster").getString("host"));
			Vertx.clusteredVertx(options, cluster -> {
				if (cluster.succeeded()) {
					Vertx vertx = cluster.result();
					vertx.deployVerticle(AuthServiceVerticle.class.getName(), new DeploymentOptions().setConfig(conf.getJsonObject("auth")), res -> {
						if (res.succeeded()) {
							LOGGER.info("Deployment id is: " + res.result());
						} else {
							LOGGER.error("Deployment failed!");
						}
					});
				} else {
					LOGGER.error("Cluster up failed: " + cluster.cause());
				}
			});
		});

	}
}
