# Prompt the user for the project name
$projectName = Read-Host "Enter your NestJS project name"

# Install NestJS globally (if not already installed)
npm install -g @nestjs/cli

# Create a new NestJS app
nest new $projectName

# Navigate into the project directory
cd $projectName

# Start the application
npm run start
