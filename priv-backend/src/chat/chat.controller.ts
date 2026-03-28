import { Body, Controller, Get, Post, Query } from '@nestjs/common';
import { ChatService } from './chat.service';
import { SendMessageDto } from './chat.dto';

@Controller('chat')
export class ChatController {
    constructor (
        private chatService: ChatService
    ) {}

    @Post('send')
    async sendMessage( @Body() dto: SendMessageDto) {
        return this.chatService.saveMessage(dto.senderId, dto.receiverId, dto.content)
    }

    @Get('history')
    async getHistory( 
        @Query('user1') user1: string,
        @Query('user2') user2: string,
    ) {
        return this.chatService.getMessages(user1, user2);
    }
}
