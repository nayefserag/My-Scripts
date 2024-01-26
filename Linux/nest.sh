read -p "Enter your NestJS project name: " projectName

npm install -g @nestjs/cli

nest new "$projectName"

cd "$projectName"

npm run start
