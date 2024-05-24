#!/bin/bash

# Function to create a new Borg repository
create_repository() {
  echo "Enter the path for the new repository:"
  read repo_path
  borg init --encryption=repokey "$repo_path"
  echo "Repository created at $repo_path"
}

# Function to check if a Borg repository exists
check_repository() {
  echo "Enter the path of the repository:"
  read repo_path
  if borg info "$repo_path" >/dev/null 2>&1; then
    echo "Repository found at $repo_path"
    return 0
  else
    echo "Repository not found at $repo_path"
    return 1
  fi
}

# Function to create a backup
create_backup() {
  if ! check_repository; then
    echo "Would you like to create a new repository at this location? (y/n)"
    read create_repo
    if [ "$create_repo" = "y" ]; then
      create_repository
    else
      echo "Cannot create a backup without a repository. Exiting."
      return
    fi
  fi

  echo "Enter the path of the directory to back up:"
  read dir_path
  echo "Enter a name for the backup archive (leave empty for default):"
  read archive_name
  if [ -z "$archive_name" ]; then
    archive_name=$(date +backup-%Y-%m-%d_%H-%M-%S)
  fi
  borg create "$repo_path::$archive_name" "$dir_path"
  echo "Backup $archive_name created in repository $repo_path"
}

# Function to list all archives in the repository
list_archives() {
  echo "Enter the path of the repository:"
  read repo_path
  borg list "$repo_path"
}

# Function to extract files from a backup
extract_files() {
  echo "Enter the path of the repository:"
  read repo_path
  echo "Enter the name of the archive to extract from:"
  read archive_name
  echo "Enter the path to extract files to (leave empty to extract to current directory):"
  read extract_path
  if [ -z "$extract_path" ]; then
    borg extract "$repo_path::$archive_name"
  else
    borg extract "$repo_path::$archive_name" --target "$extract_path"
  fi
  echo "Files extracted from $archive_name"
}

# Function to prune old backups
prune_backups() {
  echo "Enter the path of the repository:"
  read repo_path
  echo "Enter the retention policy (leave empty for default policy):"
  echo "Default: Keep everything from the last 14 days, Keep twice daily from the last 28 days,"
  echo "Keep 1 daily from the last 3 months, Keep 1 weekly from the last year, Keep 1 monthly from before that."
  read retention_policy
  if [ -z "$retention_policy" ]; then
    retention_policy="--keep-within=14d --keep-daily=56 --keep-weekly=12 --keep-monthly=12"
  fi
  borg prune -v --list "$repo_path" $retention_policy
  echo "Backups pruned according to policy: $retention_policy"
}

# Main menu
while true; do
  echo "BorgBackup Interactive Script"
  echo "1. Create a new repository"
  echo "2. Create a backup"
  echo "3. List all archives"
  echo "4. Extract files from a backup"
  echo "5. Prune old backups"
  echo "6. Exit"
  echo "Choose an option (1-6):"
  read option

  case $option in
    1)
      create_repository
      ;;
    2)
      create_backup
      ;;
    3)
      list_archives
      ;;
    4)
      extract_files
      ;;
    5)
      prune_backups
      ;;
    6)
      echo "Exiting script. Goodbye!"
      break
      ;;
    *)
      echo "Invalid option. Please choose a number between 1 and 6."
      ;;
  esac
done
