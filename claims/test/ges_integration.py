# Add to auth/ges_integration.py
class GESService:
    # ... existing methods ...
    
    def get_all_user_namespaces(self, username: str) -> Dict[str, List[str]]:
        """
        Discover and get ALL namespaces and groups for a user from GES
        """
        try:
            # This is where you'd implement namespace discovery
            # Since we don't know all possible namespaces, we need a way to discover them
            
            # Option 1: If GES provides a way to list all namespaces, use that
            # Option 2: Use a predefined list from configuration
            # Option 3: Try common namespace patterns
            
            # For now, let's assume we have a way to get common namespaces
            # You'll need to implement the actual namespace discovery based on your GES setup
            common_namespaces = self.discover_namespaces()
            
            if not common_namespaces:
                logger.warning("No GES namespaces discovered")
                return {}
            
            logger.info(f"Checking user '{username}' in discovered namespaces: {common_namespaces}")
            return self.get_user_groups_in_namespaces(username, common_namespaces)
            
        except Exception as e:
            logger.error(f"Error getting all user namespaces: {str(e)}")
            return {}
    
    def discover_namespaces(self) -> List[str]:
        """
        Discover available namespaces in GES
        This needs to be implemented based on your GES setup
        """
        # TODO: Implement namespace discovery
        # This could be:
        # - Reading from a configuration file
        # - Calling a GES API to list namespaces  
        # - Using environment variables
        # - Hardcoded list of known namespaces
        
        # For now, return an empty list - you need to implement this
        return []
