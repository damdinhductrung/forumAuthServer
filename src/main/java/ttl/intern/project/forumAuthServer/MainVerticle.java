package ttl.intern.project.forumAuthServer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import io.vertx.core.spi.cluster.ClusterManager;
import io.vertx.spi.cluster.hazelcast.HazelcastClusterManager;

public class MainVerticle extends AbstractVerticle {
	
	private static Logger LOGGER = LoggerFactory.getLogger(MainVerticle.class);

	public static void main(String[] args) {		
		
		ClusterManager mgr = new HazelcastClusterManager();
		   VertxOptions options = new VertxOptions().setClusterManager(mgr).setClusterHost("192.168.0.100");
		   Vertx.clusteredVertx(options, cluster -> {
		       if (cluster.succeeded()) {
		           cluster.result().deployVerticle(AuthServiceVerticle.class.getName(), res -> {
		               if(res.succeeded()){
		                   LOGGER.info("Deployment id is: " + res.result());
		               } else {
		                   LOGGER.error("Deployment failed!");
		               }
		           });
		       } else {
		           LOGGER.error("Cluster up failed: " + cluster.cause());
		       }
		   });
	}
}
