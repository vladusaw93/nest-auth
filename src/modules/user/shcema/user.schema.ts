import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

export type UserDocument = User & Document;

@Schema()
export class User {
  _id?: Types.ObjectId;

  @Prop()
  active: boolean;

  @Prop()
  password: string;

  @Prop({ unique: true })
  email: string;

  @Prop({ nullable: true })
  refresh_token?: string;
}

export const UserSchema = SchemaFactory.createForClass(User);
