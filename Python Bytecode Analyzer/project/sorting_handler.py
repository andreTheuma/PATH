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
            set(Identifier, <linxenumber>.<offset>): Statement_metadata in order
        """
        sorted_statement_ids = sorted(relations['Statement_Metadata'], key=self.take_second_key)
        return sorted_statement_ids

    #TODO: Change implementation to use one function
    '''
    def sort_push_values(self,relations):
        """Function which sorts the push value set in the order it is disassmbled

        Args:
            relations (set[(_,_)]): List of all the sets; Push_Values,Pop_Values,...
            statement_metadata (Identifier, <linenumber>.<offset>): Statement Metadata tuple
        """
        sorted_statement_ids = list()

        statement_metadata = self.sort_metadata(relations)

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
    
    def sort_stmt_pushes(self, relations):
        """Function which sorts the pushes on the stack in the order it is disassmbled

        Args:
            relations (set[(_,_)]): List of all the sets; Push_Values,Pop_Values,...
            statement_metadata (Identifier, <linenumber>.<offset>): Statement Metadata tuple
        """
        sorted_statement_ids = list()

        statement_metadata = self.sort_metadata(relations)

        dict_metadata = dict(statement_metadata)
        dict_pushes = dict(relations['Statement_Pushes'])

        ordered_ids = list()
        unordered_ids = list()

        #storing the ordered IDs so as to sort the unordered IDs
        for tuple in statement_metadata:
            ordered_ids.append(tuple[0])

        for tuple in relations['Statement_Pushes']:
            unordered_ids.append(tuple[0])

        for ordered_tuple in statement_metadata:
            line_value = ordered_tuple[1]
            id_value = ordered_tuple[0]

            # if key exists obtain value
            if id_value in unordered_ids:
        
                sorted_statement_ids.append((id_value,dict_pushes[id_value]))

        return sorted_statement_ids

    def sort_stmt_pops(self, relations):
        """Function which sorts the pops on the stack in the order it is disassmbled

        Args:
            relations (set[(_,_)]): List of all the sets; Push_Values,Pop_Values,...
            statement_metadata (Identifier, <linenumber>.<offset>): Statement Metadata tuple
        """
        
        sorted_statement_ids = list()
        statement_metadata = self.sort_metadata(relations)

        dict_metadata = dict(statement_metadata)
        dict_pops = dict(relations['Statement_Pops'])

        ordered_ids = list()
        unordered_ids = list()

        #storing the ordered IDs so as to sort the unordered IDs
        for tuple in statement_metadata:
            ordered_ids.append(tuple[0])

        for tuple in relations['Statement_Pops']:
            unordered_ids.append(tuple[0])

        for ordered_tuple in statement_metadata:
            line_value = ordered_tuple[1]
            id_value = ordered_tuple[0]

            # if key exists obtain value
            if id_value in unordered_ids:
        
                sorted_statement_ids.append((id_value,dict_pops[id_value]))

        return sorted_statement_ids

    def sort_stmt_opcodes(self, relations):
        """Function which sorts the opcodes on the stack in the order it is disassmbled

        Args:
            relations (set[(_,_)]): List of all the sets; Push_Values,Pop_Values,...
            statement_metadata (Identifier, <linenumber>.<offset>): Statement Metadata tuple
        """
        
        sorted_statement_ids = list()
        statement_metadata = self.sort_metadata(relations)

        dict_metadata = dict(statement_metadata)
        dict_opcodes = dict(relations['Statement_Opcode'])

        ordered_ids = list()
        unordered_ids = list()

        #storing the ordered IDs so as to sort the unordered IDs
        for tuple in statement_metadata:
            ordered_ids.append(tuple[0])

        for tuple in relations['Statement_Opcode']:
            unordered_ids.append(tuple[0])

        for ordered_tuple in statement_metadata:
            line_value = ordered_tuple[1]
            id_value = ordered_tuple[0]

            # if key exists obtain value
            if id_value in unordered_ids:
        
                sorted_statement_ids.append((id_value,dict_opcodes[id_value]))

        return sorted_statement_ids

    def sort_stmt_code(self, relations):
        """Function which sorts the code obj address on the stack in the order it is disassmbled

        Args:
            relations (set[(_,_)]): List of all the sets; Push_Values,Pop_Values,...
            statement_metadata (Identifier, <linenumber>.<offset>): Statement Metadata tuple
        """
        
        sorted_statement_ids = list()
        statement_metadata = self.sort_metadata(relations)

        dict_metadata = dict(statement_metadata)
        dict_code = dict(relations['Statement_Code'])

        ordered_ids = list()
        unordered_ids = list()

        #storing the ordered IDs so as to sort the unordered IDs
        for tuple in statement_metadata:
            ordered_ids.append(tuple[0])

        for tuple in relations['Statement_Code']:
            unordered_ids.append(tuple[0])

        for ordered_tuple in statement_metadata:
            line_value = ordered_tuple[1]
            id_value = ordered_tuple[0]

            # if key exists obtain value
            if id_value in unordered_ids:
        
                sorted_statement_ids.append((id_value,dict_code[id_value]))

        return sorted_statement_ids

    def sort_stmt_block(self, relations):
        
        sorted_statement_ids = list()
        statement_metadata = self.sort_metadata(relations)

        dict_metadata = dict(statement_metadata)
        dict_blocks = dict(relations['Statement_Block'])

        ordered_ids = list()
        unordered_ids = list()

        #storing the ordered IDs so as to sort the unordered IDs
        for tuple in statement_metadata:
            ordered_ids.append(tuple[0])

        for tuple in relations['Statement_Block']:
            unordered_ids.append(tuple[0])

        for ordered_tuple in statement_metadata:
            line_value = ordered_tuple[1]
            id_value = ordered_tuple[0]

            # if key exists obtain value
            if id_value in unordered_ids:
        
                sorted_statement_ids.append((id_value,dict_blocks[id_value]))

        return sorted_statement_ids
   
    def sort_stmt_stack_delta(self, relations):
        
        sorted_statement_ids = list()
        statement_metadata = self.sort_metadata(relations)

        dict_metadata = dict(statement_metadata)
        dict_stack_sizes = dict(relations['Statement_Stack_Delta'])

        ordered_ids = list()
        unordered_ids = list()

        #storing the ordered IDs so as to sort the unordered IDs
        for tuple in statement_metadata:
            ordered_ids.append(tuple[0])

        for tuple in relations['Statement_Stack_Delta']:
            unordered_ids.append(tuple[0])

        for ordered_tuple in statement_metadata:
            line_value = ordered_tuple[1]
            id_value = ordered_tuple[0]

            # if key exists obtain value
            if id_value in unordered_ids:
        
                sorted_statement_ids.append((id_value,dict_stack_sizes[id_value]))

        return sorted_statement_ids
    
    def sort_stmt_block_stack_delta(self, relations):
        
        sorted_statement_ids = list()
        statement_metadata = self.sort_metadata(relations)

        dict_metadata = dict(statement_metadata)
        dict_stack_sizes = dict(relations['Statement_Block_Stack_Delta'])

        ordered_ids = list()
        unordered_ids = list()

        #storing the ordered IDs so as to sort the unordered IDs
        for tuple in statement_metadata:
            ordered_ids.append(tuple[0])

        for tuple in relations['Statement_Block_Stack_Delta']:
            unordered_ids.append(tuple[0])

        for ordered_tuple in statement_metadata:
            line_value = ordered_tuple[1]
            id_value = ordered_tuple[0]

            # if key exists obtain value
            if id_value in unordered_ids:
        
                sorted_statement_ids.append((id_value,dict_stack_sizes[id_value]))

        return sorted_statement_ids
    
    def sort_stmt_pop_delta(self, relations):
        
        sorted_statement_ids = list()
        statement_metadata = self.sort_metadata(relations)

        dict_metadata = dict(statement_metadata)
        dict_pops = dict(relations['Statement_Pop_Delta'])

        ordered_ids = list()
        unordered_ids = list()

        #storing the ordered IDs so as to sort the unordered IDs
        for tuple in statement_metadata:
            ordered_ids.append(tuple[0])

        for tuple in relations['Statement_Pop_Delta']:
            unordered_ids.append(tuple[0])

        for ordered_tuple in statement_metadata:
            line_value = ordered_tuple[1]
            id_value = ordered_tuple[0]

            # if key exists obtain value
            if id_value in unordered_ids:
        
                sorted_statement_ids.append((id_value,dict_pops[id_value]))

        return sorted_statement_ids
    
    def sort_stmt_uses_local(self, relations):
        
        sorted_statement_ids = list()
        statement_metadata = self.sort_metadata(relations)

        dict_metadata = dict(statement_metadata)
        dict_pops = dict(relations['Statement_Uses_Local'])

        ordered_ids = list()
        unordered_ids = list()

        #storing the ordered IDs so as to sort the unordered IDs
        for tuple in statement_metadata:
            ordered_ids.append(tuple[0])

        for tuple in relations['Statement_Uses_Local']:
            unordered_ids.append(tuple[0])

        for ordered_tuple in statement_metadata:
            line_value = ordered_tuple[1]
            id_value = ordered_tuple[0]

            # if key exists obtain value
            if id_value in unordered_ids:
        
                sorted_statement_ids.append((id_value,dict_pops[id_value]))

        return sorted_statement_ids
'''
    def general_stmt_sorter(self,relations,relation):
        
        sorted_statement_ids = list()
        statement_metadata = self.sort_metadata(relations)

        dict_metadata = dict(statement_metadata)
        dict_relation = dict(relations[relation])

        ordered_ids = list()
        unordered_ids = list()

        #storing the ordered IDs so as to sort the unordered IDs
        for tuple in statement_metadata:
            ordered_ids.append(tuple[0])

        for tuple in relations[relation]:
            unordered_ids.append(tuple[0])

        for ordered_tuple in statement_metadata:
            line_value = ordered_tuple[1]
            id_value = ordered_tuple[0]

            # if key exists obtain value
            if id_value in unordered_ids:
        
                sorted_statement_ids.append((id_value,dict_relation[id_value]))

        return sorted_statement_ids
    
    