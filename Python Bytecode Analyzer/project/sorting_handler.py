class sorting_handler:

    def take_second_key(self,item):
        """
        Retrieves the key of the item to be sorted by.

        Args:
            item (int): the int used to sort the values by
        Returns:
            int: value at the index of the item key
        """
        return item[1]

    def take_third_key(self,item): 
        return item[2]

    def sort_metadata(self,relations):
        """Function which sorts the metadata set in the order it is disassembled 
        in dis.dis()

        Args:
            relations (set[(_,_)]) : List of all the sets; Push_Values,Pop_Values,...

        Returns:
            set(Identifier, <linenumber>.<offset>): Statement_metadata in order
        """
        sorted_statement_ids = sorted(relations['Statement_Metadata'], key=self.take_second_key)
        return sorted_statement_ids

    def sort_push_values(self,relations, statement_metadata):
        """Function which sorts the push value set in the order it is disassmbled

        Args:
            relations (set[(_,_)]): List of all the sets; Push_Values,Pop_Values,...
            statement_metadata (Identifier, <linenumber>.<offset>): Statement Metadata tuple
        """
        sorted_statement_ids = list()

        dict_metadata = dict(statement_metadata)
        dict_pushval = dict(relations['PushValue'])

        ordered_ids = list()
        unordered_ids = list()

        #storing the ordered IDs so as to sort the unordered IDs
        for tuple in statement_metadata:
            ordered_ids.append(tuple[0])

        for tuple in relations['PushValue']:
            unordered_ids.append(tuple[0])

        for ordered_tuple in statement_metadata:
            line_value = ordered_tuple[1]
            id_value = ordered_tuple[0]

            # if key exists obtain value
            if id_value in unordered_ids:
        
                sorted_statement_ids.append((id_value,dict_pushval[id_value]))

        return sorted_statement_ids