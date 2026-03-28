import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class ChatService {
    constructor (
        private prisma: PrismaService
    ) {}

    async saveMessage(senderId:string, receiverId: string, content: string) {
        return this.prisma.message.create({
            data: {
                senderId,
                receiverId, 
                encryptedContent: content,
            }
        })
    }

    async getMessages(user1: string, user2: string) {
        return this.prisma.message.findMany({
            where: {
                OR: [
                    { senderId: user1, receiverId: user2 },
                    { senderId: user2, receiverId: user1 }
                ]
            },
            orderBy: { createdAt: 'asc' }
        })
    }
}
