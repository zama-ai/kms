for container in `docker ps -q`; do 
  # show the name of the container
  docker inspect --format='{{.Name}}' $container;
  # run the command (must be in docker dir)
  docker exec -it $container $1;
done